/*
 * ipmiservicelogd.c
 *
 * A program that listens to IPMI events and writes them
 * out to servicelog.
 *
 * Author: International Business Machines, IBM
 *         Mark Hamzy <hamzy@us.ibm.com>
 * Author: Intel Corporation
 *         Jeff Zheng <Jeff.Zheng@Intel.com>
 *
 * Copyright 2009 International Business Machines, IBM
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* gcc -o ipmiservicelogd -g `pkg-config --cflags --libs OpenIPMI OpenIPMIposix servicelog-1` ipmiservicelogd.c
 */
/* ./ipmiservicelogd smi 0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_fru.h>

#include <servicelog.h>

#include <crm/crm.h>

#define COMPLEX 1

static os_handler_t *os_hnd;

char *getStringExecOutput(char *args[]);
char *getSerialNumber(void);
char *getProductName(void);
static void con_usage(const char *name, const char *help, void *cb_data);
static void usage(const char *progname);
void ipmi2servicelog(struct sl_data_bmc *bmc_data);
static int sensor_threshold_event_handler(ipmi_sensor_t * sensor, enum ipmi_event_dir_e dir,
                                          enum ipmi_thresh_e threshold,
                                          enum ipmi_event_value_dir_e high_low,
                                          enum ipmi_value_present_e value_present,
                                          unsigned int raw_value, double value, void *cb_data,
                                          ipmi_event_t * event);
static int sensor_discrete_event_handler(ipmi_sensor_t * sensor, enum ipmi_event_dir_e dir,
                                         int offset, int severity, int prev_severity, void *cb_data,
                                         ipmi_event_t * event);
static void sensor_change(enum ipmi_update_e op, ipmi_entity_t * ent, ipmi_sensor_t * sensor,
                          void *cb_data);
static void entity_change(enum ipmi_update_e op, ipmi_domain_t * domain, ipmi_entity_t * entity,
                          void *cb_data);
void setup_done(ipmi_domain_t * domain, int err, unsigned int conn_num, unsigned int port_num,
                int still_connected, void *user_data);

char *
getStringExecOutput(char *args[])
{
    int rc;
    pid_t pid;
    int pipefd[2];

    rc = pipe2(pipefd, 0);

    if (rc == -1) {

        crm_err("Error: pipe errno = %d", errno);

        return NULL;
    }

    pid = fork();

    if (0 < pid) {

        /* Parent */
        int childExitStatus;
        char serialNumber[256];
        ssize_t sizeRead;

        /* close write end of pipe */
        rc = close(pipefd[1]);
        if (rc == -1) {
            crm_err("Error: parent close (pipefd[1]) = %d", errno);
        }

        /* make 0 same as read-from end of pipe */
        rc = dup2(pipefd[0], 0);
        if (rc == -1) {
            crm_err("Error: parent dup2 (pipefd[0]) = %d", errno);
        }

        /* close excess fildes */
        rc = close(pipefd[0]);
        if (rc == -1) {
            crm_err("Error: parent close (pipefd[0]) = %d", errno);
        }

        waitpid(pid, &childExitStatus, 0);

        if (!WIFEXITED(childExitStatus)) {

            crm_err("waitpid() exited with an error: status = %d", WEXITSTATUS(childExitStatus));

            return NULL;

        } else if (WIFSIGNALED(childExitStatus)) {

            crm_err("waitpid() exited due to a signal = %d", WTERMSIG(childExitStatus));

            return NULL;

        }

        memset(serialNumber, 0, sizeof(serialNumber));

        sizeRead = read(0, serialNumber, sizeof(serialNumber) - 1);

        if (sizeRead > 0) {

            char *end = serialNumber + strlen(serialNumber) - 1;
            char *retSerialNumber = NULL;

            while (end > serialNumber
                   && (*end == '\n' || *end == '\r' || *end == '\t' || *end == ' ')
                ) {
                *end = '\0';
                end--;
            }

            retSerialNumber = malloc(strlen(serialNumber) + 1);

            if (retSerialNumber) {

                strcpy(retSerialNumber, serialNumber);

            }

            return retSerialNumber;

        }

        return NULL;

    } else if (pid == 0) {

        /* Child */

        /* close read end of pipe */
        rc = close(pipefd[0]);
        if (rc == -1) {
            crm_err("Error: child close (pipefd[0]) = %d", errno);
        }

        /* make 1 same as write-to end of pipe */
        rc = dup2(pipefd[1], 1);
        if (rc == -1) {
            crm_err("Error: child dup2 (pipefd[1]) = %d", errno);
        }

        /* close excess fildes */
        rc = close(pipefd[1]);
        if (rc == -1) {
            crm_err("Error: child close (pipefd[1]) = %d", errno);
        }

        rc = execvp(args[0], args);

        if (rc == -1) {
            crm_err("Error: child execvp = %d", errno);
        }

        /* In case of error */
        return NULL;

    } else {

        /* Error */
        crm_err("fork errno = %d", errno);

        return NULL;
    }

    return NULL;
}

char *
getSerialNumber(void)
{
    char *dmiArgs[] = {
        "dmidecode",
        "--string",
        "system-serial-number",
        NULL
    };

    return getStringExecOutput(dmiArgs);
}

char *
getProductName(void)
{
    char *dmiArgs[] = {
        "dmidecode",
        "--string",
        "system-product-name",
        NULL
    };

    return getStringExecOutput(dmiArgs);
}

static void
con_usage(const char *name, const char *help, void *cb_data)
{
    printf("\n%s%s", name, help);
}

static void
usage(const char *progname)
{
    printf("Usage:\n");
    printf(" %s <con_parms>\n", progname);
    printf(" Where <con_parms> is one of:");
    ipmi_parse_args_iter_help(con_usage, NULL);
}

void
ipmi2servicelog(struct sl_data_bmc *bmc_data)
{
    servicelog *slog = NULL;
    struct sl_event sl_event;
    uint64_t new_id = 0;
    struct utsname name;
    char *serial_number = NULL;
    char *product_name = NULL;
    int rc;

    if (uname(&name) == -1) {
        crm_err("Error: uname failed");
        return;
    }

    rc = servicelog_open(&slog, 0);     /* flags is one of SL_FLAG_xxx */

    if (!slog) {
        crm_err("Error: servicelog_open failed, rc = %d", rc);
        return;
    }

    serial_number = getSerialNumber();
    if (serial_number) {
        if (strlen(serial_number) > 20) {
            serial_number[20] = '\0';
        }
    }

    product_name = getProductName();
    if (product_name) {
        if (strlen(product_name) > 20) {
            product_name[20] = '\0';
        }
    }

    memset(&sl_event, 0, sizeof(sl_event));

/* *INDENT-OFF* */
    sl_event.next             = NULL;                 /* only used if in a linked list */
    sl_event.id               = 0;                    /* unique identifier - filled in by API call */
    sl_event.time_logged      = time (NULL);
    sl_event.time_event       = time (NULL);
    sl_event.time_last_update = time (NULL);
    sl_event.type             = SL_TYPE_BMC;          /* one of SL_TYPE_* */
    sl_event.severity         = SL_SEV_WARNING;       /* one of SL_SEV_* */
    sl_event.platform         = name.machine;         /* ppc64, etc */
    sl_event.machine_serial   = serial_number;
    sl_event.machine_model    = product_name;         /* it may not have the serial # within the first 20 chars */
    sl_event.nodename         = name.nodename;
    sl_event.refcode          = "ipmi";
    sl_event.description      = "ipmi event";
    sl_event.serviceable      = 1;                    /* 1 or 0 */
    sl_event.predictive       = 0;                    /* 1 or 0 */
    sl_event.disposition      = SL_DISP_RECOVERABLE;  /* one of SL_DISP_* */
    sl_event.call_home_status = SL_CALLHOME_NONE;     /* one of SL_CALLHOME_*,
                                                      only valid if serviceable */
    sl_event.closed           = 1;                    /* 1 or 0, only valid if serviceable */
    sl_event.repair           = 0;                    /* id of repairing repair_action */
    sl_event.callouts         = NULL;
    sl_event.raw_data_len     = 0;
    sl_event.raw_data         = NULL;
    sl_event.addl_data        = &bmc_data;            /* pointer to an sl_data_* struct */
/* *INDENT-ON* */

    rc = servicelog_event_log(slog, &sl_event, &new_id);

    if (rc != 0) {
        crm_err("Error: servicelog_event_log, rc = %d (\"%s\")", rc, servicelog_error(slog));
    } else {
        crm_debug("Sending to servicelog database");
    }

    free(serial_number);
    free(product_name);

    servicelog_close(slog);
}

static int
sensor_threshold_event_handler(ipmi_sensor_t * sensor,
                               enum ipmi_event_dir_e dir,
                               enum ipmi_thresh_e threshold,
                               enum ipmi_event_value_dir_e high_low,
                               enum ipmi_value_present_e value_present,
                               unsigned int raw_value,
                               double value, void *cb_data, ipmi_event_t * event)
{
    ipmi_entity_t *ent = ipmi_sensor_get_entity(sensor);
    int id, instance;
    char name[IPMI_ENTITY_NAME_LEN];
    struct sl_data_bmc bmc_data;
    uint32_t sel_id;
    uint32_t sel_type;
    uint16_t generator;
    uint8_t version;
    uint8_t sensor_type;
    int sensor_lun;
    int sensor_number;
    uint8_t event_class;
    uint8_t event_type;
    int direction;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, sizeof(name));

    ipmi_sensor_get_num(sensor, &sensor_lun, &sensor_number);

    sel_id = ipmi_entity_get_entity_id(ent);
    sel_type = ipmi_entity_get_type(ent);
    generator = ipmi_entity_get_slave_address(ent) | (sensor_lun << 5); /* LUN (2 bits) | SLAVE ADDRESS (5 bits) */
    version = 0x04;
    sensor_type = ipmi_sensor_get_sensor_type(sensor);
    event_class = 0;            /* @TBD - where does this come from? */
    event_type = ipmi_event_get_type(event);
    direction = dir;

    memset(&bmc_data, 0, sizeof(bmc_data));

    bmc_data.sel_id = sel_id;
    bmc_data.sel_type = sel_type;
    bmc_data.generator = generator;
    bmc_data.version = version;
    bmc_data.sensor_type = sensor_type;
    bmc_data.sensor_number = sensor_number;
    bmc_data.event_class = event_class;
    bmc_data.event_type = event_type;
    bmc_data.direction = direction;

    crm_debug("Writing bmc_data (%08x, %08x, %04x, %02x, %02x, %02x, %02x, %02x, %d)\n",
              bmc_data.sel_id,
              bmc_data.sel_type,
              bmc_data.generator,
              bmc_data.version,
              bmc_data.sensor_type,
              bmc_data.sensor_number,
              bmc_data.event_class, bmc_data.event_type, bmc_data.direction);

    ipmi2servicelog(&bmc_data);

    /* This passes the event on to the main event handler, which does
       not exist in this program. */
    return IPMI_EVENT_NOT_HANDLED;
}

static int
sensor_discrete_event_handler(ipmi_sensor_t * sensor,
                              enum ipmi_event_dir_e dir,
                              int offset,
                              int severity, int prev_severity, void *cb_data, ipmi_event_t * event)
{
    ipmi_entity_t *ent = ipmi_sensor_get_entity(sensor);
    int id, instance;
    char name[IPMI_ENTITY_NAME_LEN];
    struct sl_data_bmc bmc_data;
    uint32_t sel_id;
    uint32_t sel_type;
    uint16_t generator;
    uint8_t version;
    uint8_t sensor_type;
    int sensor_lun;
    int sensor_number;
    uint8_t event_class;
    uint8_t event_type;
    int direction;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, sizeof(name));

    sel_id = ipmi_entity_get_entity_id(ent);
    sel_type = ipmi_entity_get_type(ent);
    generator = ipmi_entity_get_slave_address(ent) | (sensor_lun << 5); /* LUN (2 bits) | SLAVE ADDRESS (5 bits) */
    version = 0x04;
    sensor_type = ipmi_sensor_get_sensor_type(sensor);

    ipmi_sensor_get_num(sensor, &sensor_lun, &sensor_number);

    event_class = 0;            /* @TBD - where does this come from? */
    event_type = ipmi_event_get_type(event);
    direction = dir;

    memset(&bmc_data, 0, sizeof(bmc_data));

    bmc_data.sel_id = sel_id;
    bmc_data.sel_type = sel_type;
    bmc_data.generator = generator;
    bmc_data.version = version;
    bmc_data.sensor_type = sensor_type;
    bmc_data.sensor_number = sensor_number;
    bmc_data.event_class = event_class;
    bmc_data.event_type = event_type;
    bmc_data.direction = direction;

    crm_debug("Writing bmc_data (%08x, %08x, %04x, %02x, %02x, %02x, %02x, %02x, %d)\n",
              bmc_data.sel_id,
              bmc_data.sel_type,
              bmc_data.generator,
              bmc_data.version,
              bmc_data.sensor_type,
              bmc_data.sensor_number,
              bmc_data.event_class, bmc_data.event_type, bmc_data.direction);

    ipmi2servicelog(&bmc_data);

    /* This passes the event on to the main event handler, which does
       not exist in this program. */
    return IPMI_EVENT_NOT_HANDLED;
}

/* Whenever the status of a sensor changes, the function is called
   We display the information of the sensor if we find a new sensor
*/
static void
sensor_change(enum ipmi_update_e op, ipmi_entity_t * ent, ipmi_sensor_t * sensor, void *cb_data)
{
    int rv;

    if (op == IPMI_ADDED) {
        if (ipmi_sensor_get_event_reading_type(sensor) == IPMI_EVENT_READING_TYPE_THRESHOLD)
            rv = ipmi_sensor_add_threshold_event_handler(sensor,
                                                         sensor_threshold_event_handler, NULL);
        else
            rv = ipmi_sensor_add_discrete_event_handler(sensor,
                                                        sensor_discrete_event_handler, NULL);
        if (rv)
            crm_err("Unable to add the sensor event handler: %x", rv);
    }
}

/* Whenever the status of an entity changes, the function is called
   When a new entity is created, we search all sensors that belong 
   to the entity */
static void
entity_change(enum ipmi_update_e op, ipmi_domain_t * domain, ipmi_entity_t * entity, void *cb_data)
{
    int rv;
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    if (op == IPMI_ADDED) {
        /* Register callback so that when the status of a
           sensor changes, sensor_change is called */
        rv = ipmi_entity_add_sensor_update_handler(entity, sensor_change, entity);
        if (rv) {
            crm_err("ipmi_entity_set_sensor_update_handler: 0x%x", rv);
            crm_exit(pcmk_err_generic);
        }
    }
}

/* After we have established connection to domain, this function get called
   At this time, we can do whatever things we want to do. Herr we want to
   search all entities in the system */
void
setup_done(ipmi_domain_t * domain,
           int err,
           unsigned int conn_num, unsigned int port_num, int still_connected, void *user_data)
{
    int rv;

    /* Register a callback functin entity_change. When a new entities 
       is created, entity_change is called */
    rv = ipmi_domain_add_entity_update_handler(domain, entity_change, domain);
    if (rv) {
        crm_err("ipmi_domain_add_entity_update_handler return error: %d", rv);
        return;
    }

}

int
main(int argc, char *argv[])
{
    int rv;
    int curr_arg = 1;
    ipmi_args_t *args;
    ipmi_con_t *con;

    /* OS handler allocated first. */
    os_hnd = ipmi_posix_setup_os_handler();
    if (!os_hnd) {
        crm_err("ipmi_smi_setup_con: Unable to allocate os handler");
        crm_exit(pcmk_err_generic);
    }

    /* Initialize the OpenIPMI library. */
    ipmi_init(os_hnd);

#ifdef COMPLEX
    rv = ipmi_parse_args2(&curr_arg, argc, argv, &args);
    if (rv) {
        crm_err("Error parsing command arguments, argument %d: %s", curr_arg, strerror(rv));
        usage(argv[0]);
        crm_exit(pcmk_err_generic);
    }
#endif

    crm_make_daemon("ipmiservicelogd", TRUE, "/var/run/ipmiservicelogd.pid0");

    crm_log_init("ipmiservicelogd", LOG_INFO, FALSE, TRUE, argc, argv);

#ifdef COMPLEX
    rv = ipmi_args_setup_con(args, os_hnd, NULL, &con);
    if (rv) {
        crm_err("ipmi_ip_setup_con: %s", strerror(rv));
        crm_err("Error: Is IPMI configured correctly?");
        crm_exit(pcmk_err_generic);
    }
#else
    /* If all you need is an SMI connection, this is all the code you
       need. */
    /* Establish connections to domain through system interface.  This
       function connect domain, selector and OS handler together.
       When there is response message from domain, the status of file
       descriptor in selector is changed and predefined callback is
       called. After the connection is established, setup_done will be
       called. */
    rv = ipmi_smi_setup_con(0, os_hnd, NULL, &con);
    if (rv) {
        crm_err("ipmi_smi_setup_con: %s", strerror(rv));
        crm_err("Error: Is IPMI configured correctly?");
        crm_exit(pcmk_err_generic);
    }
#endif

    rv = ipmi_open_domain("", &con, 1, setup_done, NULL, NULL, NULL, NULL, 0, NULL);
    if (rv) {
        crm_err("ipmi_init_domain: %s", strerror(rv));
        crm_exit(pcmk_err_generic);
    }

    /* This is the main loop of the event-driven program. 
       Try <CTRL-C> to exit the program */
    /* Let the selector code run the select loop. */
    os_hnd->operation_loop(os_hnd);

    /* Technically, we can't get here, but this is an example. */
    os_hnd->free_os_handler(os_hnd);
}
