/*
 * POWERNV debug  perf driver to export inband occ_sensors
 *
 * (C) Copyright IBM 2016
 *
 * Bhargav Reddy <bhargav431994@gmail.com>
 *
 * Usage:
 * Build this driver against your kernel and load the module.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/io.h>
#include <linux/perf_event.h>

#include <asm/cputhreads.h>

#define BE(x, s)	be_to_cpu(x, s)

struct sensor_attr {
	char *name;
	const char *unit;
	char *event_name;  /* event configuration number */
	char *scale;
	char *scale_name;
	char *unit_name;
	u64 paddr;
	u64 vaddr;
	u32 size;
	struct device_attribute attr;
};

struct core_attr {
	struct sensor_attr *sensors;
};

struct chip {
	int id;
	char *name;
	int nr_cores;
	u64 pbase;
	u64 vbase;
	struct sensor_attr *sensors;
	struct core_attr *cores;
} *chips;

struct sensor_attr *system_sensors;
struct sensor_attr *power_cap_sensors;
struct attribute **sensor_event_attrs;
struct perf_pmu_events_attr *sensor_event_list;
int total_num_sensors;

static unsigned int nr_chips, nr_system_sensors, nr_power_cap_sensors;
static unsigned int nr_chip_sensors, nr_core_sensors;
static cpumask_t sensor_cpu_mask;

unsigned long be_to_cpu(u64 addr, u32 size)
{
	switch (size) {
	case 16:
		return __be16_to_cpu(*(u16 *)addr);
	case 32:
		return __be32_to_cpu(*(u32 *)addr);
	case 64:
		return __be64_to_cpu(*(u64 *)addr);
	}
	return 0;
}

static void destructor(struct sensor_attr *sensor, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		kfree(sensor[i].name);
		kfree(sensor[i].scale);
		kfree(sensor[i].event_name);
		kfree(sensor[i].unit_name);
		kfree(sensor[i].scale_name);
	}
	kfree(sensor);
}

static ssize_t sensor_attr_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct sensor_attr *sensor_temp = container_of(attr,
			struct sensor_attr, attr);

	return sprintf(buf, "%lu %s\n", BE(sensor_temp->vaddr,
				sensor_temp->size), sensor_temp->unit);
}

#define add_sensor(node, var, len, reg)					\
do {									\
	if (of_property_read_u64(node, "reg", &var.paddr)) {		\
		pr_info("%s node cannot read reg property\n", node->name);\
		continue;						\
	}								\
	reg = of_get_property(node, "reg", &len);			\
	var.size = of_read_number(reg, 3) * 8 * sizeof(char);		\
	if (of_property_read_string(node, "unit", &var.unit)) {		\
		pr_info("%s node cannot read unit\n", node->name);	\
	} \
	var.vaddr = (u64)phys_to_virt(var.paddr);			\
	pr_info("Sensor : %s *(%lx) *(size:%u)= %lu\n", node->name,	\
		(unsigned long)var.vaddr, var.size, BE(var.vaddr, var.size));\
	var.attr.attr.mode = S_IRUGO;					   \
	var.attr.show = sensor_attr_show;				   \
	var.attr.store = NULL;						   \
} while (0)

static int add_system_sensor(struct device_node *snode)
{
	struct device_node *node;
	const __be32 *reg;
	int len, i = 0;

	for_each_child_of_node(snode, node) {
		add_sensor(node, system_sensors[i], len, reg);
		system_sensors[i].name = kmalloc(30, GFP_KERNEL);
		sprintf(system_sensors[i].name, "%s", node->name);
		system_sensors[i].attr.attr.name = system_sensors[i].name;
		i++;
	}

	return 0;
}

static int add_power_cap_sensor(struct device_node *snode)
{
	struct device_node *node;
	const __be32 *reg;
	int len, i = 0;

	for_each_child_of_node(snode, node) {
		add_sensor(node, power_cap_sensors[i], len, reg);
		power_cap_sensors[i].name = kmalloc(30, GFP_KERNEL);
		sprintf(power_cap_sensors[i].name, "%s", node->name);
		power_cap_sensors[i].attr.attr.name = power_cap_sensors[i].name;
		i++;
	}

	return 0;
}

static int add_core_sensor(struct device_node *cnode, int chipid, int cid)
{
	const __be32 *reg;
	struct device_node *node;
	int i = 0, len;
	unsigned int id;

	if (of_property_read_u32(cnode, "ibm,core-id", &id)) {
		pr_info("Core_id not found");
		return -EINVAL;
	}
	for_each_child_of_node(cnode, node) {
		add_sensor(node, chips[chipid].cores[cid].sensors[i], len, reg);
		chips[chipid].cores[cid].sensors[i].name = kmalloc(30,
				GFP_KERNEL);
		sprintf(chips[chipid].cores[cid].sensors[i].name,
				"chip%d-core%d-%s", chipid+1, cid+1,
				node->name);
		chips[chipid].cores[cid].sensors[i].attr.attr.name =
			chips[chipid].cores[cid].sensors[i].name;
		i++;
	}
	return 0;
}

static int add_chip_sensor(struct device_node *chip_node)
{
	const __be32 *reg;
	u32 len;
	struct device_node *node;
	int i, j, k, rc = 0;
	u32 id = 0;

	if (of_property_read_u32(chip_node, "ibm,chip-id", &id)) {
		pr_err("Chip not found\n");
		goto out;
	}
	for (i = 0; i < nr_chips; i++)
		if (chips[i].id == id)
			break;

	if (of_property_read_u64(chip_node, "reg", &chips[i].pbase)) {
		pr_err("Chip Homer sensor offset not found\n");
		rc = -ENODEV;
		goto out;
	}

	chips[i].vbase = (u64)phys_to_virt(chips[i].pbase);
	pr_info("i = %d Chip %d sensor pbase= %lx, vbase = %lx (%lx)\n", i,
		 chips[i].id, (unsigned long)chips[i].pbase,
		 (unsigned long)chips[i].vbase, BE(chips[i].vbase+4, 16));

	j = k = 0;
	for_each_child_of_node(chip_node, node) {
		if (!strcmp(node->name, "core")) {
			add_core_sensor(node, i, k++);
			continue;
		}
		add_sensor(node, chips[i].sensors[j], len, reg);
		chips[i].sensors[j].name = kmalloc(30, GFP_KERNEL);
		sprintf(chips[i].sensors[j].name, "chip%d-%s", i+1, node->name);
		chips[i].sensors[j].attr.attr.name = chips[i].sensors[j].name;
		j++;
	}
out:
	return rc;
}


static int init_chip(void)
{
	unsigned int chip[256];
	unsigned int cpu, i, j;
	unsigned int prev_chip_id = UINT_MAX;
	struct device_node *sensor_node, *node;
	int rc = 0;

	for_each_possible_cpu(cpu) {
		unsigned int id = cpu_to_chip_id(cpu);

		if (prev_chip_id != id) {
			bool id_added = false;
			int j;

			for (j = 0; j < nr_chips; j++)
				if (chip[j] == id) {
					id_added = true;
					break;
				}
			if (id_added)
				continue;
			prev_chip_id = id;
			chip[nr_chips++] = id;
		}
	}
	pr_info("nr_chips %d\n", nr_chips);
	chips = kcalloc(nr_chips, sizeof(struct chip), GFP_KERNEL);
	if (!chips) {
		pr_info("Out of memory\n");
		return -ENOMEM;
	}

	for (i = 0; i < nr_chips; i++) {
		int ncpus = 0;

		chips[i].id = chip[i];
		for_each_possible_cpu(cpu)
			if (chips[i].id == cpu_to_chip_id(cpu))
				ncpus++;
		chips[i].nr_cores = ncpus / threads_per_core;
	}

	sensor_node = of_find_node_by_path("/occ_sensors");

	if (of_property_read_u32(sensor_node, "nr_system_sensors",
				 &nr_system_sensors)) {
		pr_info("nr_system_sensors not found\n");
		return -EINVAL;
	}

	if (of_property_read_u32(sensor_node, "nr_chip_sensors",
				 &nr_chip_sensors)) {
		pr_info("nr_chip_sensors not found\n");
		return -EINVAL;
	}
	if (of_property_read_u32(sensor_node, "nr_core_sensors",
				 &nr_core_sensors)) {
		pr_info("nr_core_sensors not found\n");
		return -EINVAL;
	}
	if (of_property_read_u32(sensor_node, "nr_power_cap_sensors",
				&nr_power_cap_sensors)){
		pr_info("nr_power_cap_sensors not found\n");
	}

	system_sensors = kcalloc(nr_system_sensors, sizeof(struct sensor_attr),
			GFP_KERNEL);
	power_cap_sensors = kcalloc(nr_power_cap_sensors,
			sizeof(struct sensor_attr),
			GFP_KERNEL);

	for (i = 0; i < nr_chips; i++) {
		chips[i].sensors = kcalloc(nr_chip_sensors,
				sizeof(struct sensor_attr), GFP_KERNEL);
		chips[i].cores = kcalloc(chips[i].nr_cores,
				sizeof(struct core_attr), GFP_KERNEL);
		for (j = 0; j < chips[i].nr_cores; j++)
			chips[i].cores[j].sensors = kcalloc(nr_core_sensors,
					sizeof(struct sensor_attr), GFP_KERNEL);
	}

	for_each_child_of_node(sensor_node, node) {
		if (!strcmp(node->name, "chip"))
			rc = add_chip_sensor(node);
		else if (!strcmp(node->name, "system_sensor"))
			rc = add_system_sensor(node);
		else
			rc = add_power_cap_sensor(node);
		if (rc)
			goto out;
	}

out:
	return rc;
}

static ssize_t sensor_get_attr_cpumask(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &sensor_cpu_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, sensor_get_attr_cpumask, NULL);

static struct attribute *sensor_pmu_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group sensor_pmu_attr_group = {
	.attrs = sensor_pmu_attrs,
};

size_t sensor_event_sysfs_show(struct device *dev,
		struct device_attribute *attr, char *page)
{
	struct perf_pmu_events_attr *pmu_attr =	container_of(attr,
			struct perf_pmu_events_attr, attr);

	if (pmu_attr->event_str)
		return sprintf(page, "%s\n", pmu_attr->event_str);
	return 0;
}

PMU_FORMAT_ATTR(event, "config:0-30");

static struct attribute *sensor_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group sensor_format_group = {
	.name = "format",
	.attrs = sensor_format_attrs,
};

/*can be  used to statically add the attributes to the sensor_event_group */
#define OCC_EVENT_ATTR(name, var, str)					\
static struct perf_pmu_events_attr event_attr_##var = {			\
	.attr = __ATTR(name, 0444, sensor_event_sysfs_show, NULL),	\
	.event_str = str,						\
}

struct attribute_group sensor_event_group = {
	.name = "events",
	.attrs = NULL,	/* allocated at runtime */
};

static struct perf_pmu_events_attr *dev_str_attr(const char *name,
		char *str, int event_file_num)
{
	struct perf_pmu_events_attr *attr;

	attr = &sensor_event_list[event_file_num-1];
	attr->attr.attr.name = name;
	attr->attr.attr.mode = 0444;
	attr->attr.show = sensor_event_sysfs_show;
	attr->attr.store = NULL;
	attr->event_str = str;
	return attr;
}


static void add_sensor_to_event_group(struct sensor_attr *sensor, int event_num)
{
	struct perf_pmu_events_attr *p;

	sensor->event_name = kmalloc(30, GFP_KERNEL);
	sprintf(sensor->event_name, "event=0x%x", event_num);
	sensor->unit_name = kmalloc(30, GFP_KERNEL);
	sprintf(sensor->unit_name, "%s.unit",
			sensor->name);
	sensor->scale_name = kmalloc(30, GFP_KERNEL);
	sprintf(sensor->scale_name, "%s.scale",
			sensor->name);
	p = dev_str_attr(sensor->name, sensor->event_name, 3*(event_num-1)+0);
	sensor_event_attrs[3*(event_num-1)+0] = &(p->attr.attr);
	p = dev_str_attr(sensor->unit_name, (char *)sensor->unit,
			3*(event_num-1)+1);
	sensor_event_attrs[3*(event_num-1)+1] = &(p->attr.attr);
	p = dev_str_attr(sensor->scale_name, "1", 3*(event_num-1)+2);
	sensor_event_attrs[3*(event_num-1)+2] = &(p->attr.attr);
}


static int update_events_in_group(void)
{
	int i, j, k;
	int rc = 0;

	total_num_sensors = 0;
	total_num_sensors += nr_system_sensors;
	total_num_sensors += nr_power_cap_sensors;
	for (j = 0; j < nr_chips; j++) {
		total_num_sensors += nr_chip_sensors;
		for (k = 0; k < chips[j].nr_cores; k++)
			total_num_sensors += nr_core_sensors;
	}
	sensor_event_attrs = kzalloc(sizeof(struct device_attribute *) *
			(3*total_num_sensors), GFP_KERNEL);
	if (!sensor_event_attrs) {
		rc = -ENOMEM;
		pr_info("allocate system_event_attrs failed");
		goto out;
	}
	sensor_event_list = kzalloc(sizeof(struct perf_pmu_events_attr) *
			(3*total_num_sensors), GFP_KERNEL);
	if (!sensor_event_list) {
		rc = -ENOMEM;
		pr_info("allocate system_device_attrs failed");
		goto out;
	}
	for (i = 0; i < nr_system_sensors; i++)
		add_sensor_to_event_group(&system_sensors[i], i+1);

	for (j = 0; j < nr_power_cap_sensors; j++, i++)
		add_sensor_to_event_group(&power_cap_sensors[j], i+1);

	for (j = 0; j < nr_chips; j++) {
		for (k = 0; k < nr_chip_sensors; k++, i++)
			add_sensor_to_event_group(&chips[j].sensors[k], i+1);

		for (k = 0; k < chips[j].nr_cores; k++) {
			int l;

			for (l = 0; l < nr_core_sensors; l++, i++) {
				add_sensor_to_event_group(
						&chips[j].cores[k].sensors[l],
						i+1);
			}
		}
	}
	sensor_event_group.attrs = sensor_event_attrs;
	pr_info("update_events_in_group passed\n");
out:
	return rc;
}


struct attribute_group *sensor_attr_groups[] = {
	&sensor_pmu_attr_group,
	&sensor_event_group,
	&sensor_format_group,
	NULL,
};


static u32 event_config_to_addr_size_map(int config_minus_one)
{
	int config = config_minus_one;
	int temp = 0;
	int j, k;
	int sensor_locator = nr_system_sensors;

	if (config < nr_system_sensors)
		return system_sensors[config].size;
	temp = sensor_locator;
	sensor_locator += nr_power_cap_sensors;
	if (config < sensor_locator)
		return power_cap_sensors[config-temp].size;
	for (j = 0; j < nr_chips; j++) {
		temp = sensor_locator;
		sensor_locator += nr_chip_sensors;
		if (config < sensor_locator)
			return chips[j].sensors[config-temp].size;
		for (k = 0; k < chips[j].nr_cores; k++) {
			temp = sensor_locator;
			sensor_locator += nr_core_sensors;
			if (config < sensor_locator)
				return chips[j].cores[k].
					sensors[config-temp].size;
		}
	}
	return 0;
}


static void sensor_pmu_event_read_counter(struct perf_event *event)
{
	u64 addr = event->hw.event_base;
	u64 data = 0;
	u32 size = event_config_to_addr_size_map(event->attr.config-1);

	if (size > 0)
		data = BE(addr, size);
	local64_set(&event->hw.prev_count, data);
}

static void sensor_pmu_event_read_sample(struct perf_event *event)
{
	u64 addr;
	u16 data;

	addr = event->hw.event_base;
	data = BE((addr), 16);
	local64_set(&event->hw.prev_count, data);
	local64_set(&event->count, data);
}

static void sensor_pmu_event_update(struct perf_event *event)
{
	u64 addr;
	u64 counter_new, counter_prev;
	s64 final_count;
	u32 size;

	size = event_config_to_addr_size_map(event->attr.config-1);
	addr = event->hw.event_base;
	if (size == 16 || size == 32)
		counter_new = BE(addr, size);
	else
		return;
	counter_prev = local64_read(&event->hw.prev_count);
	final_count = counter_new - counter_prev;

	local64_set(&event->hw.prev_count, counter_new);
	local64_add(final_count, &event->count);
}

static void sensor_pmu_event_read(struct perf_event *event)
{
	u32 size = event_config_to_addr_size_map(event->attr.config-1);

	switch (size) {
	case 8: /* to read the sensor of 1 byte size*/
		sensor_pmu_event_read_sample(event);
		break;
	case 16:/* to read and add the sensor of 2 bytes size  */
		sensor_pmu_event_update(event);
		break;
	case 32: /*to read and add the sensor of 4 bytes size */
		sensor_pmu_event_update(event);
		break;
	default:
		break;
	}
}
static void sensor_pmu_event_stop(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_UPDATE)
		sensor_pmu_event_read(event);
}

static void sensor_pmu_event_start(struct perf_event *event, int flags)
{
	sensor_pmu_event_read_counter(event);
}

static int sensor_pmu_event_add(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_START)
		sensor_pmu_event_start(event, flags);
	return 0;
}

static u64 event_config_to_vaddr_map(int config_minus_one)
{
	int config = config_minus_one;
	int temp = 0;
	int j, k;
	int sensor_locator = nr_system_sensors;

	if (config < nr_system_sensors)
		return system_sensors[config].vaddr;
	temp = sensor_locator;
	sensor_locator += nr_power_cap_sensors;
	if (config < sensor_locator)
		return power_cap_sensors[config-temp].vaddr;
	for (j = 0; j < nr_chips; j++) {
		temp = sensor_locator;
		sensor_locator += nr_chip_sensors;
		if (config < sensor_locator)
			return chips[j].sensors[config-temp].vaddr;
		for (k = 0; k < chips[j].nr_cores; k++) {
			temp = sensor_locator;
			sensor_locator += nr_core_sensors;
			if (config < sensor_locator)
				return chips[j].cores[k].
					sensors[config-temp].vaddr;
		}
	}
	return -EINVAL;
}

static int sensor_pmu_event_init(struct perf_event *event)
{
	u64 vaddr;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;
	if (event->attr.exclude_user	||
			event->attr.exclude_kernel ||
			event->attr.exclude_hv     ||
			event->attr.exclude_idle   ||
			event->attr.exclude_host   ||
			event->attr.exclude_guest  ||
			event->hw.sample_period)
		return -EINVAL;

	vaddr = event_config_to_vaddr_map(event->attr.config-1);
	if (vaddr > 0)
		event->hw.event_base = vaddr;
	else
		return -EINVAL;
	return 0;
}

static u64 sensor_pmu_event_count(struct perf_event *event)
{
	u64 data;
	u64 addr = event->hw.event_base;
	u32 size = event_config_to_addr_size_map(event->attr.config-1);

	if (size > 0) {
		data = BE(addr, size);
		return data;
	}
	return -EINVAL;
}

static struct pmu sensor_pmu = {
	.attr_groups	= sensor_attr_groups,
	.event_init     = sensor_pmu_event_init,
	.add            = sensor_pmu_event_add,
	.del            = sensor_pmu_event_stop,
	.start          = sensor_pmu_event_start,
	.stop           = sensor_pmu_event_stop,
	.read           = sensor_pmu_event_read,
	.count          = sensor_pmu_event_count,
};


static int sensor_init(void)
{
	int rc;

	rc = init_chip();
	if (rc)
		goto out;
	update_events_in_group();
	rc = perf_pmu_register(&sensor_pmu, "occ_power", -1);
	if (rc) {
		pr_info("perf_pmu_register failed\n");
		goto out;
	} else
		pr_info("perf_pmu_register passed\n");
	cpumask_set_cpu(0, &sensor_cpu_mask);
out:
	return rc;
}



static void sensor_exit(void)
{
	int i, j;

	perf_pmu_unregister(&sensor_pmu);
	pr_info("unlocked perf");

	destructor(system_sensors, nr_system_sensors);
	destructor(power_cap_sensors, nr_power_cap_sensors);
	for (i = 0; i < nr_chips; i++) {
		destructor(chips[i].sensors, nr_chip_sensors);
		for (j = 0; j < chips[i].nr_cores; j++)
			destructor(chips[i].cores[j].sensors, nr_core_sensors);
		kfree(chips[i].cores);
	}
	for (i = 0; i < total_num_sensors; i++)
		kfree(sensor_event_attrs[i]);
	kfree(sensor_event_list);
	kfree(sensor_event_attrs);
	kfree(chips);
}


module_init(sensor_init);
module_exit(sensor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhargav Reddy <bhargav431994 at gmail dot com>");
