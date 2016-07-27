/*
 * Perf driver for OCC-inabnd sensors supported on POWERNV
 *
 * (C) Copyright IBM 2016
 *
 * Author :
 * Bhargav Reddy <bhargav431994@gmail.com>
 *
 * Licence:
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
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

struct sensor {
	char *name;
	char *unit;
	char *event_name;  /* event configuration number */
	char *scale;
	char *scale_name;
	char *unit_name;
	u64 paddr;
	u64 vaddr;
	u32 size;
	struct device_attribute attr;
};

struct core {
	struct sensor *sensors;
};

struct chip {
	int id;
	int nr_cores;
	struct sensor *sensors;
	struct core *cores;
} *chips;

#define CHAR_BIT 8
/*
 * Each sensor has three perf files a)config b)unit
 * c)scale associated with it
*/
#define NR_PERF_FILES 3
struct sensor *system_sensors;
struct sensor *power_cap_sensors;

struct attribute **sensor_event_attrs;
struct perf_pmu_events_attr *sensor_event_list;
static int total_num_sensors;
static u32 *event_addr_size_map;
static u64 *event_vaddr_map;
static unsigned int nr_chips, nr_system_sensors, nr_power_cap_sensors;
static unsigned int nr_chip_sensors, nr_core_sensors;
static cpumask_t sensor_cpu_mask;

static inline unsigned long be_to_cpu(u64 addr, u32 size)
{
	switch (size) {
	case 8:
		return *(u8 *)addr;
	case 16:
		return __be16_to_cpu(*(u16 *)addr);
	case 32:
		return __be32_to_cpu(*(u32 *)addr);
	case 64:
		return __be64_to_cpu(*(u64 *)addr);
	}
	return 0;
}

static void clean_sensor_array(struct sensor *sensor, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		kfree(sensor[i].name);
		kfree(sensor[i].unit);
		kfree(sensor[i].scale);
		kfree(sensor[i].event_name);
		kfree(sensor[i].unit_name);
		kfree(sensor[i].scale_name);
	}
	kfree(sensor);
}

static void clean_all_sensors(void)
{
	int i, j;

	clean_sensor_array(system_sensors, nr_system_sensors);
        clean_sensor_array(power_cap_sensors, nr_power_cap_sensors);
	for (i = 0; i < nr_chips; i++) {
                clean_sensor_array(chips[i].sensors, nr_chip_sensors);
                for (j = 0; j < chips[i].nr_cores; j++)
                        clean_sensor_array(chips[i].cores[j].sensors,
						nr_core_sensors);
                kfree(chips[i].cores);
        }
        kfree(chips);
}

static void clean_all_event_data(void)
{
	int i;

	kfree(event_addr_size_map);
	kfree(event_vaddr_map);
	for (i = 0; i < total_num_sensors; i++)
                kfree(sensor_event_attrs[i]);
        kfree(sensor_event_list);
        kfree(sensor_event_attrs);

}

#define add_sensor(node, var, rc)				\
do {\
	int len;\
	const __be32 *node_reg;\
	const char *temp;						\
	if (of_property_read_u64(node, "reg", &var.paddr)) {		\
		pr_info("%s node cannot read reg property\n", node->name);\
		rc = -ENODEV;						\
		continue;						\
	}								\
	node_reg = of_get_property(node, "reg", &len);			\
	var.size = of_read_number(node_reg, 3) * CHAR_BIT * sizeof(char);\
	if (of_property_read_string(node, "unit", &temp)) {		\
		pr_info("%s node cannot read unit\n", node->name);	\
		rc = -ENODEV;						\
		continue;						\
	}								\
	var.unit = kmalloc(strlen(temp)+1, GFP_KERNEL);			\
	sprintf(var.unit, "%s", temp);					\
	if (of_property_read_string(node, "scale", &temp)) {             \
                pr_info("%s node cannot read scale\n", node->name);      \
                rc = -ENODEV;                                           \
                continue;                                               \
        }                                                               \
        var.scale = kmalloc(strlen(temp)+1, GFP_KERNEL);                 \
        sprintf(var.scale, "%s", temp);                                  \
	var.vaddr = (u64)phys_to_virt(var.paddr);			\
	pr_debug("Sensor : %s *(%lx) *(size:%u)= %lu\n", node->name,	\
		(unsigned long)var.vaddr, var.size, BE(var.vaddr, var.size));\
	rc = 0;								\
} while (0)

static int add_sensor_type(struct device_node *snode,
		struct sensor *sensors_type)
{
	struct device_node *node;
	int rc, i = 0;

	for_each_child_of_node(snode, node) {
		add_sensor(node, sensors_type[i], rc);
		if (rc) {
			pr_info("failed to add %s sensor\n", node->name);
			return rc;
                }

		sensors_type[i].name = kmalloc(strlen(node->name)+1, GFP_KERNEL);
		sprintf(sensors_type[i].name, "%s", node->name);
		i++;
	}
	return 0;
}

static inline int add_system_sensor(struct device_node *snode)
{
	return add_sensor_type(snode, system_sensors);
}

static inline int add_power_cap_sensor(struct device_node *snode)
{
	return add_sensor_type(snode, power_cap_sensors);
}

static int add_core_sensor(struct device_node *cnode, int chipid, int cid)
{
	struct device_node *node;
	int rc, i = 0;
	unsigned int id;
	char temp[30];

	if (of_property_read_u32(cnode, "ibm,core-id", &id)) {
		pr_info("Core_id not found");
		return -EINVAL;
	}
	for_each_child_of_node(cnode, node) {
		add_sensor(node, chips[chipid].cores[cid].sensors[i], rc);
		if (rc) {
			pr_info("failed to add %s sensor\n", node->name);
			return rc;
		}
		sprintf(temp, "chip%d-core%d-%s", chipid+1, cid+1, node->name);
		chips[chipid].cores[cid].sensors[i].name = kmalloc(strlen(temp)+1,
				GFP_KERNEL);
		sprintf(chips[chipid].cores[cid].sensors[i].name, "%s", temp);
		i++;
	}
	return 0;
}

static int add_chip_sensor(struct device_node *chip_node)
{
	struct device_node *node;
	int rc, i, j, k = 0;
	u32 id = 0;
	char temp[30];

	if (of_property_read_u32(chip_node, "ibm,chip-id", &id)) {
		pr_err("Chip not found\n");
		rc = -ENODEV;
		goto out;
	}
	for (i = 0; i < nr_chips; i++) {
		if (chips[i].id == id)
			break;
	}
	j = k = 0;
	for_each_child_of_node(chip_node, node) {
		if (!strcmp(node->name, "core")) {
			add_core_sensor(node, i, k++);
			continue;
		}
		add_sensor(node, chips[i].sensors[j], rc);
		if (rc) {
			pr_info("failed to add %s sensor\n", node->name);
			goto out;
		}
		sprintf(temp, "chip%d-%s", i+1, node->name);
		chips[i].sensors[j].name = kmalloc(strlen(temp)+1, GFP_KERNEL);
		sprintf(chips[i].sensors[j].name, "%s", temp);
		j++;
	}
	return 0;
out:
	return rc;
}

static int populate_sensors(void)
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

			for (j = 0; j < nr_chips; j++) {
				if (chip[j] == id) {
					id_added = true;
					break;
				}
			}
			if (id_added)
				continue;
			prev_chip_id = id;
			chip[nr_chips++] = id;
		}
	}
	pr_debug("nr_chips %d\n", nr_chips);

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
		return -EINVAL;
	}
	system_sensors = kcalloc(nr_system_sensors, sizeof(struct sensor),
			GFP_KERNEL);
	if (!system_sensors) {
                pr_info("could not allocate mempory for system sensors\n");
		return -ENOMEM;
        }
	power_cap_sensors = kcalloc(nr_power_cap_sensors,
			sizeof(struct sensor),
			GFP_KERNEL);
	if (!power_cap_sensors) {
                pr_info("could not allocate mempory for power-cap sensors\n");
		kfree(system_sensors);
                return -ENOMEM;
        }

	chips = kcalloc(nr_chips, sizeof(struct chip), GFP_KERNEL);
        if (!chips) {
                pr_info("could not allocate mempory for chips\n");
                kfree(system_sensors);
		kfree(power_cap_sensors);
		return -ENOMEM;
        }
        for (i = 0; i < nr_chips; i++) {
                int ncpus = 0;

                chips[i].id = chip[i];
                for_each_possible_cpu(cpu) {
                        if (chips[i].id == cpu_to_chip_id(cpu))
                                ncpus++;
		}
                chips[i].nr_cores = ncpus / threads_per_core;
        }

	for (i = 0; i < nr_chips; i++) {
		chips[i].sensors = kcalloc(nr_chip_sensors,
				sizeof(struct sensor), GFP_KERNEL);
		chips[i].cores = kcalloc(chips[i].nr_cores,
				sizeof(struct core), GFP_KERNEL);
		for (j = 0; j < chips[i].nr_cores; j++)
			chips[i].cores[j].sensors = kcalloc(nr_core_sensors,
					sizeof(struct sensor), GFP_KERNEL);
	}
	for_each_child_of_node(sensor_node, node) {
		if (!strcmp(node->name, "chip"))
			rc = add_chip_sensor(node);
		else if (!strcmp(node->name, "system_sensor"))
			rc = add_system_sensor(node);
		else if (!strcmp(node->name, "power_cap_sensor"))
			rc = add_power_cap_sensor(node);
		else {
			pr_info("Unidentified sensor");
			rc = -ENODEV;
			goto out;
		}
		if (rc)
			goto out;
	}
	pr_debug("init done");
	return 0;
out:
	clean_all_sensors();
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

ssize_t sensor_event_sysfs_show(struct device *dev,
		struct device_attribute *attr, char *page)
{
	struct perf_pmu_events_attr *pmu_attr =	container_of(attr,
			struct perf_pmu_events_attr, attr);

	if (pmu_attr->event_str)
		return sprintf(page, "%s\n", pmu_attr->event_str);
	return 0;
}

PMU_FORMAT_ATTR(event, "config:0-7");

static struct attribute *sensor_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group sensor_format_group = {
	.name = "format",
	.attrs = sensor_format_attrs,
};

static void add_to_event_map(int pos, int size, u64 vaddr)
{
	event_addr_size_map[pos] = size;
	event_vaddr_map[pos] = vaddr;
}

struct attribute_group sensor_event_group = {
	.name = "events",
	.attrs = NULL,	/* allocated at runtime */
};

static struct perf_pmu_events_attr *dev_str_attr(const char *name,
		char *str, int event_file_num)
{
	struct perf_pmu_events_attr *attr;

	attr = &sensor_event_list[event_file_num];
	attr->attr.attr.name = name;
	attr->attr.attr.mode = 0444;
	attr->attr.show = sensor_event_sysfs_show;
	attr->attr.store = NULL;
	attr->event_str = str;
	return attr;
}

/*
 * Every sensor is associated with a perf-event which enables to read the
 * sensor. event_num is the event->attr.config of the corresponding perf-event
 * for the sensor. Each perf event has the following 3 files
 * a)event config, b)event unit, c)event scale.
*/
enum perf_event_files {
	EVENT_CONFIG=0,
	EVENT_UNIT=1,
	EVENT_SCALE=2,
};
	
static inline int get_event_file(int event_num, enum perf_event_files event_file)
{
	return 3*(event_num-1) + event_file;
}

static void add_sensor_to_event_group(struct sensor *sensor,
		int event_num)
{
	struct perf_pmu_events_attr *p;
	char temp[30];

	add_to_event_map(event_num-1, sensor->size, sensor->vaddr);
	sprintf(temp, "event=0x%x", event_num);
	sensor->event_name = kmalloc(strlen(temp)+1, GFP_KERNEL);
	sprintf(sensor->event_name, "%s", temp);
	sprintf(temp, "%s.unit", sensor->name);
	sensor->unit_name = kmalloc(strlen(temp)+1, GFP_KERNEL);
	sprintf(sensor->unit_name, "%s", temp);
	sprintf(temp, "%s.scale", sensor->name);
	sensor->scale_name = kmalloc(strlen(temp)+1, GFP_KERNEL);
	sprintf(sensor->scale_name, "%s", temp);
	p = dev_str_attr(sensor->name, sensor->event_name,
			get_event_file(event_num, EVENT_CONFIG));
	sensor_event_attrs[get_event_file(event_num, EVENT_CONFIG)] =
		&(p->attr.attr);
	p = dev_str_attr(sensor->unit_name, sensor->unit,
			get_event_file(event_num, EVENT_UNIT));
	sensor_event_attrs[get_event_file(event_num, EVENT_UNIT)] =
		&(p->attr.attr);
	p = dev_str_attr(sensor->scale_name, sensor->scale,
			get_event_file(event_num, EVENT_SCALE));
	sensor_event_attrs[get_event_file(event_num, EVENT_SCALE)] =
		&(p->attr.attr);
}

static int update_events_in_group(void)
{
	int i, j, k;
	int rc = 0;

	total_num_sensors = nr_system_sensors + nr_power_cap_sensors;
	for (j = 0; j < nr_chips; j++) {
		total_num_sensors += nr_chip_sensors;
		total_num_sensors += chips[j].nr_cores * nr_core_sensors;
	}
	sensor_event_attrs = kzalloc(sizeof(struct device_attribute *) *
			(NR_PERF_FILES * total_num_sensors), GFP_KERNEL);
	if (!sensor_event_attrs) {
                pr_info("allocate sensor_event_attrs failed");
                return -ENOMEM;
        }
	event_addr_size_map = kzalloc(sizeof(u32) * total_num_sensors,
			GFP_KERNEL);
	if (!event_addr_size_map) {
                rc = -ENOMEM;
                pr_info("allocate event_addr_size_map failed");
                goto out;
        }
	event_vaddr_map = kzalloc(sizeof(u64) * total_num_sensors, GFP_KERNEL);
	if (!event_vaddr_map) {
                rc = -ENOMEM;
                pr_info("allocate event_vaddr_map failed");
                goto out;
        }
	sensor_event_list = kzalloc(sizeof(struct perf_pmu_events_attr) *
			(NR_PERF_FILES * total_num_sensors), GFP_KERNEL);
	if (!sensor_event_list) {
		rc = -ENOMEM;
		pr_info("allocate sensor_event_list failed");
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
	pr_debug("update_events_in_group passed\n");
	return 0;
out:
	clean_all_event_data();
	return rc;
}

const struct attribute_group *sensor_groups[] = {
	&sensor_pmu_attr_group,
	&sensor_event_group,
	&sensor_format_group,
	NULL,
};

static void sensor_pmu_event_read_counter(struct perf_event *event)
{
	u64 addr = event->hw.event_base;
	u64 data = 0;
	u32 size = event_addr_size_map[event->attr.config-1];

	if (size > 0)
		data = BE(addr, size);
	local64_set(&event->hw.prev_count, data);
}

static void sensor_pmu_event_read_sample(struct perf_event *event)
{
	u64 addr;
	u64 data;
	u32 size;

	size = event_addr_size_map[event->attr.config-1];
	addr = event->hw.event_base;
	if (size == 16 || size == 8)
		data = BE(addr, size);
	else {
		pr_info("Incomaptible size requested.");
		pr_info("Should be one or two bytes for sampling events");
		return;
	}
	local64_set(&event->hw.prev_count, data);
	local64_set(&event->count, data);
}

static void sensor_pmu_event_update(struct perf_event *event)
{
	u64 addr;
	u64 counter_new, counter_prev;
	s64 final_count;
	u32 size;

	size = event_addr_size_map[event->attr.config-1];
	addr = event->hw.event_base;
	if (size == 64 || size == 32)
		counter_new = BE(addr, size);
	else {
		pr_info("Incompatible size requested.");
		pr_info("Should be 4 or 8 bytes for aggregate counting event");
		return;
	}
	counter_prev = local64_read(&event->hw.prev_count);
	final_count = counter_new - counter_prev;
	local64_set(&event->hw.prev_count, counter_new);
	local64_add(final_count, &event->count);
}

static void sensor_pmu_event_read(struct perf_event *event)
{
	u32 size = event_addr_size_map[event->attr.config-1];

	switch (size) {
	case 8: /* to read the sensor of 1 byte size*/
		sensor_pmu_event_read_sample(event);
		break;
	case 16:/* to read and add the sensor of 2 bytes size  */
		sensor_pmu_event_read_sample(event);
		break;
	case 32: /*to read and add the sensor of 4 bytes size */
		sensor_pmu_event_update(event);
		break;
	case 64: /*to read and add the sensor of 8 bytes size */
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

	vaddr = event_vaddr_map[event->attr.config-1];
	if (vaddr > 0)
		event->hw.event_base = vaddr;
	else
		return -EINVAL;
	return 0;
}

static struct pmu sensor_pmu = {
	.attr_groups	= sensor_groups,
	.event_init     = sensor_pmu_event_init,
	.add            = sensor_pmu_event_add,
	.del            = sensor_pmu_event_stop,
	.start          = sensor_pmu_event_start,
	.stop           = sensor_pmu_event_stop,
	.read           = sensor_pmu_event_read,
};

static int sensor_init(void)
{
	int rc;

	rc = populate_sensors();
	if (rc)
		return rc;
	rc = update_events_in_group();
	if(rc) {
		clean_all_sensors();
		return rc;
	}
	rc = perf_pmu_register(&sensor_pmu, "occ_power", -1);
	if (rc) {
		pr_info("register opal OCC-sensors in pmu failed\n");
		clean_all_sensors();
		clean_all_event_data();
		return rc;

	}
	else {
		pr_info("register opal OCC-sensors in pmu completed\n");
		cpumask_set_cpu(0, &sensor_cpu_mask);
	}
	return 0;
}

static void sensor_exit(void)
{
	perf_pmu_unregister(&sensor_pmu);
	pr_info("unregistered opal OCC-sensors from pmu");

	clean_all_sensors();
	clean_all_event_data();
}

module_init(sensor_init);
module_exit(sensor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhargav Reddy <bhargav431994 at gmail dot com>");
