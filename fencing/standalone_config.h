/* 
 * Copyright (C) 2012
 * David Vossel  <dvossel@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef STANDALONE_CONFIG__H
#define STANDALONE_CONFIG__H

/*! Picking a large number in effort to avoid a dynamic list. */
#define STANDALONE_CFG_MAX_KEYVALS 100

#define STONITH_NG_CONF_FILE "/etc/pacemaker/stonith-ng.conf"

/*!
 * \brief Attempts to open a stonith standalone config file
 * and load the config internally.
 *
 * \note standalone_cfg_commit() must be executed after
 * reading in the file before the config will be activated.
 *
 * \retval 0, success
 * \retval -1, failure
 */
int standalone_cfg_read_file(const char *file_path);

/*!
 * \brief Add a fencing device to the standalone config
 *
 * \param device, Name of the fencing device to be created.
 * \param agent, The underlying fencing agent this device will use.
 *
 * \retval 0, Success
 * \retval -1, Failure
 */
int standalone_cfg_add_device(const char *device, const char *agent);

/*!
 * \brief Add an option (key value pair) to an existing fencing device.
 *
 * \param device, Name of the fencing device
 * \param key, the Key portion of the key value pair.
 * \param value, the value portion of the key value pair.
 *
 * \retval 0, Success
 * \retval -1, Failure
 */
int standalone_cfg_add_device_options(const char *device, const char *key, const char *value);

/*!
 * \brief Add a node to a fencing device.
 *
 * \param node, Name of the node to add to the fencing device
 * \param device, Name of the fencing device to add the node to
 * \param ports, The port mappings of this specific node for the device, NULL if no
 *               port mapping is present.
 *
 * \retval 0, Success
 * \retval -1, failure
 */
int standalone_cfg_add_node(const char *node, const char *device, const char *ports);

/*!
 * \brief Add a fencing level rule to a node for a specific fencing device.
 */
int standalone_cfg_add_node_priority(const char *node, const char *device, unsigned int level);

/*!
 *  \brief Commits all the changes added to the standalone config into the stonithd core.
 */
int standalone_cfg_commit(void);

#endif
