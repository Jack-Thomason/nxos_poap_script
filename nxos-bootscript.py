#!/bin/env python
#md5sum="621ddd9c30670c4e71a75f82455917f1"

# Return Values:
# 0 : Reboot and reapply configuration
# -1 : Error case. This will cause POAP to restart the DHCP discovery phase.

import glob
import os
from time import gmtime, strftime, sleep
import re
import sys
import syslog
from cli import *

REMOTE_SERVER = "{{tftp_server}}"
HOSTNAME = "{{Hostname}}"
CONFIG_FILE = "{{config_file}}"
FIRMWARE_FILE = "{{firmware_file}}"

CONFIG_PROTOCOL = "tftp"
FIRMWARE_PROTOCOL = "http"
CONFIG_PATH = "bootflash:"
FIRMWARE_PATH = "bootflash:"

VRF = "management"
MD5_SRC_EXT = ".md5"

MAX_RETRIES = 3

match_firmware = re.search(r'(\d+\.\d+\.\d+)', FIRMWARE_FILE)
if match_firmware:
    TARGET_VERSION = match_firmware.group(1)
else:
    TARGET_VERSION = ""

SPACE_REQUIREMENTS = {
    'N9K-C93180YC-EX': 1073741824,  # 1GB
    'N9K-C93108TC-EX': 1073741824,
    'default': 2147483648  # 2GB default
}
 

#####################################
# *** Health checks and logging ***
#####################################


def get_space_requirement(model):
    return SPACE_REQUIREMENTS.get(model, SPACE_REQUIREMENTS['default'])


def setup_logging():
    """
    Configures the log file this script uses
    """
    global log_hdl
    poap_script_log = "/bootflash:%s_poap_%s_script.log" % (strftime("%Y%m%d%H%M%S", gmtime()),
                                                            os.environ['POAP_PID'])
    log_hdl = open(poap_script_log, "w+")
    poap_log("INFO: Logfile name: %s" % poap_script_log)
    poap_cleanup_script_logs()


def poap_cleanup_script_logs():
    """
    Deletes all the POAP log files in bootflash leaving
    recent 4 files.
    """
    file_list = sorted(glob.glob(os.path.join("/bootflash", '*poap*script.log')), reverse=True)
    poap_log("INFO: Found %d POAP script logs" % len(file_list))
    logs_for_removal = file_list[4:]
    for old_log in logs_for_removal:
        remove_file(old_log)


def remove_file(filename):
    """
    Removes a file if it exists and it's not a directory.
    """
    if os.path.isfile(filename):
        try:
            os.remove(filename)
        except (IOError, OSError) as e:
            poap_log("Failed to remove %s: %s" % (filename, str(e)))


def poap_log(info):
    """
    Log the trace into console and poap_script log file in bootflash
    Args:
        file_hdl: poap_script log bootflash file handle
        info: The information that needs to be logged.
    """
    global log_hdl, syslog_prefix

    # Don't syslog passwords
    parts = re.split("\s+", info.strip())
    for (index, part) in enumerate(parts):
        # blank out the password after the password keyword (terminal password *****, etc.)
        if part == "password" and len(parts) >= index+2:
            parts[index+1] = "<removed>"

    # Recombine for syslogging
    info = " ".join(parts)

    # We could potentially get a traceback (and trigger this) before
    # we have called init_globals. Make sure we can still log successfully
    try:
        info = "%s - %s" % (syslog_prefix, info)
    except NameError:
        info = " - %s" % info

    syslog.syslog(9, info)
    if "log_hdl" in globals() and log_hdl is not None:
        log_hdl.write("\n")
        log_hdl.write(info)
        log_hdl.flush()


def check_system_health():
    """
    Conducts system health checks: version, model, storage capacity 
    (in the event the firmware image transfer must be executed)
    """
    for attempt in range(MAX_RETRIES):
        poap_log("INFO: check_system_health (attempt %d/%d)" % ((attempt + 1), MAX_RETRIES))
        try:
            # Get model information
            model_output = cli("show version | grep 'cisco Nexus'")
            if not model_output:
                raise Exception("Could not find Nexus model information")
            
            parts = model_output.split()
            if len(parts) < 3:
                raise Exception("Unexpected show version output format")
                
            model = parts[2]
            poap_log("INFO: Device model: %s" % model)

            # Get required space based on model
            required_space = get_space_requirement(model)
            poap_log("INFO: Required space for %s: %d" % (model, required_space))

            # Check bootflash space
            free_space = cli("dir bootflash: | grep free | sed 's/.bytes free//' | awk '{print $1}'")
            free_space = int(free_space)
            poap_log("INFO: Free space on %s: %d" % (model, free_space))

            if free_space < required_space:
                poap_log("WARNING: Low bootflash space: %d bytes" % free_space)
                raise Exception("Insufficient memory for firmware upgrade")
            
            # All above tests have passed, so return true
            return True

        except Exception as e:
            poap_log("System health check failed: %s" % str(e))

    # None of the attempts resulted in success, so return false
    return False

###########################################
# *** Config download and application ***Zero
###########################################


def tftp_copy(tftp_server=REMOTE_SERVER, config_filename=CONFIG_FILE, dest="poap.cfg"):
    """
    Copies the config file provided from tftp source to destination.
    """
    poap_log("INFO: Transferring config file using TFTP from %s %s to %s" % (tftp_server, config_filename, dest))
    base_tftp_copy_cmd = "copy tftp://%s/%s %s" % (tftp_server, config_filename, dest)
    tftp_copy_cmd = base_tftp_copy_cmd + " vrf default"
    poap_log("INFO: TFTP copy command is : %s" % tftp_copy_cmd)
    try:
        cli(tftp_copy_cmd)
        if not file_exists(dest):
            raise Exception("Local file does not exist!")
        poap_log("NOTICE: Config transfer successful")

        #### change for test
        return True
    except Exception as e:
        if "no such file" in str(e):
            poap_log("ABORT: Copy of %s failed: no such file" % config_filename)
        elif "Permission denied" in str(e):
            poap_log("ABORT: Copy of %s failed: permission denied" % config_filename)
        elif "No space left on device" in str(e):
            poap_log("ABORT: Copy failed: No space left on device")
        else:
            poap_log("ABORT: Copy failed: %s" % str(e))
    return False


def file_copy(compliance, filename="poap.cfg"):
    """
    Copies the config file provided from local source to scheduled config.
    """
    
    if not compliance:
        poap_log("INFO: Transferring new config into scheduled config %s" % (filename))
        try:
            cli("copy running-config startup-config")
            cli("copy %s scheduled-config" % filename)
            # Verify scheduled-config exists
            cli("show scheduled-config")
            return True
        except Exception as e:
            if "no such file" in str(e):
                poap_log("ABORT: Copy of %s failed: no such file" % filename)
            elif "Permission denied" in str(e):
                poap_log("ABORT: Copy of %s failed: permission denied" % filename)
            elif "No space left on device" in str(e):
                poap_log("ABORT: Copy failed: No space left on device")
            else:
                poap_log("ABORT: Copy failed: %s" % str(e))
        return False
    else:
        poap_log("INFO: Transferring new config to running config %s" % (filename))
        try:
            # Apply config
            cli("copy %s running-config" % filename)  # Changed to explicit running-config
            # Verify config applied
            cli("show running-config")
            # Save to startup
            cli("copy running-config startup-config")
            # Save to scheduled just in case
            cli("copy %s scheduled-config" % filename)
            return True
        except Exception as e:
            if "no such file" in str(e):
                poap_log("ABORT: Copy of %s failed: no such file" % filename)
            elif "Permission denied" in str(e):
                poap_log("ABORT: Copy of %s failed: permission denied" % filename)
            elif "No space left on device" in str(e):
                poap_log("ABORT: Copy failed: No space left on device")
            else:
                poap_log("ABORT: Copy failed: %s" % str(e))
        return False



###########################################
# *** Firmware checks and installation ***
###########################################


def http_download(url, dest):
    """
    Copies the config file provided from http source to destination.
    """
    config_filename = CONFIG_FILE
    poap_log("INFO: Transferring using HTTP from %s to %s" % (url, dest))
    http_copy_cmd = "copy %s %s" % (url, dest)
    poap_log("INFO: HTTP copy command is : %s" % http_copy_cmd)
    try:
        cli(http_copy_cmd)
        return True
    except Exception as e:
        if "no such file" in str(e):
            poap_log("ABORT: Copy of %s failed: no such file" % config_filename)
        elif "Permission denied" in str(e):
            poap_log("ABORT: Copy of %s failed: permission denied" % config_filename)
        elif "No space left on device" in str(e):
            poap_log("ABORT: Copy failed: No space left on device")
        else:
            poap_log("ABORT: Copy failed: %s" % str(e))
    return False


def get_current_version():
    """
    Gets the current firmware version of the device
    """
    try:
        version = cli("show version")
        # Match format like 10.2(4)
        version_match = re.search(r'(\d+\.\d+\.\d+)', version)
        if version_match:
            version = version_match.group(1)
            poap_log("INFO: Current firmware version: %s" % version)
            return version
        else:
            raise Exception("Failed to parse version string: %s" % version)
    except Exception as e:
        poap_log("WARNING: Failed to get current version: %s" % str(e))
        return None


def evaluate_version_compliance():
    """
    Verifies if the current firmware version matches the target version
    Returns True if versions match or if upgrade is successful
    """
    if not TARGET_VERSION:
        poap_log("WARNING: No target version found - proceeding to config application")
        return True
    for attempt in range(MAX_RETRIES):
        poap_log("INFO: evaluate_version_compliance (attempt %d/%d)" % ((attempt + 1), MAX_RETRIES))
        try:
            current_version = get_current_version()
            if not current_version:
                raise Exception("Could not find current version")
            if current_version == TARGET_VERSION:
                poap_log("INFO: Firmware version %s matches target version" % current_version)
                poap_log("NOTICE: Device firmware is compliant")
                return True
            #Passes checks and assumes firmware is not compliant, so returns False
            poap_log("NOTICE: Firmware upgrade needed. Current: %s, Target: %s" % (current_version, TARGET_VERSION))
            return False
        except Exception as e:
            poap_log("WARNING: Evaluate version compliance failed: %s" % str(e))
    
    #Attempts to find version info exhausted, so proceed under assumption that an upgrade is required
    poap_log("WARNING: evaluate_version_compliance attempts failed - proceed with firmware upgrade")
    return False

def file_exists(filename):
    try:
        poap_log("INFO: checking if %s is in local storage" % filename)
        path = cli("dir | grep %s " % filename)
        return bool(path.strip())
    except Exception as e:
        poap_log("ERROR: File check failed: %s" % str(e))
        return False


def upgrade_firmware():
    """
    Downloads of confirms local instance of target firmware version and verifies it 
    """
    poap_log("INFO: upgrade_firmware initiated")
    firmware_file = FIRMWARE_FILE
    http_server = REMOTE_SERVER

    if file_exists(firmware_file):
        for attempt in range(MAX_RETRIES):
            poap_log("INFO: Firmware upgrade (attempt %d/%d)" % ((attempt + 1), MAX_RETRIES))
            poap_log("INFO: Compliant image is stored locally. Skipping download. Verifying...")
            if verify_firmware_image(firmware_file):
                poap_log("NOTICE: Existing firmware file verified successfully")
                return True
            else:
                poap_log("WARNING: Existing firmware file verification failed")
                cleanup_image(firmware_file)
                    
            if attempt < MAX_RETRIES - 1:
                poap_log("INFO: Retrying upgrade process...")         
            else:
                poap_log("ERROR: Firmware upgrade failed after all attempts")
                return False


    poap_log("INFO: Downloading firmware from HTTP server")
    for download_attempt in range(MAX_RETRIES):
        try:
            firmware_url = "http://%s/n9k/%s" % (http_server, firmware_file)
            dest_path = "bootflash:%s" % (firmware_file)
            if http_download(firmware_url, dest_path):
                poap_log("NOTICE: Firmware download successful. Verifying...")
                if verify_firmware_image(firmware_file):
                    poap_log("NOTICE: Firmware verified successfully. Firmware upgrade successful")
                    return True
                else: 
                    poap_log("WARNING: Download file verification failed")
                    cleanup_image(firmware_file)
            else:
                poap_log("ERROR: Download failed")
        except Exception as e:
            poap_log("ERROR: Download attempt failed: %s" % str(e))
            if file_exists(firmware_file):
                cleanup_image(firmware_file)

        if download_attempt < MAX_RETRIES - 1:
            poap_log("INFO: Retrying download...")
        else:
            poap_log("ERROR: All download attempts failed")
    return False
        
def cleanup_image(firmware_file):
    """
    Deletes firmware file from local storage
    """
    for i in range(MAX_RETRIES):
        poap_log("INFO: Deleting image from local storage (attempt %d/%d)" % ((i + 1), MAX_RETRIES))
        try:
            cli("delete bootflash:%s" % firmware_file)
            if not file_exists(firmware_file):
                poap_log("NOTICE: Successfully deleted %s" % firmware_file)
                return True
            poap_log("WARNING: File still exists after delete attempt")
        except Exception as e:
            poap_log("ERROR: Deleting firmware image attempt failed")
    return False

def verify_firmware_image(filename):
    """
    Conducts image verification test
    """
    src_md5 = get_src_md5(filename)
    if not src_md5:
        poap_log("ERROR: Could not get source MD5")
        return False
    
    dst_md5 = get_dst_md5(filename)
    if not dst_md5:
        poap_log("ERROR: Could not get destination MD5")
        return False

    #return src_md5 == dst_md5
    return False

def get_src_md5(filename):
    """
    Gets MD5 from .md5 file on HTTP server
    """
    try:
        # Construct file names
        md5_file = "%s.md5" % filename
        temp_md5_file = "volatile:%s.md5" % filename
        md5_url = "http://%s/n9k/%s" % (REMOTE_SERVER, md5_file)

        poap_log("INFO: Downloading MD5 file from %s" % md5_url)
        
        # Download MD5 file using existing http_download method
        if not http_download(md5_url, temp_md5_file):
            poap_log("ERROR: Failed to download MD5 file")
            return None

        try:
            # Read the MD5 from the downloaded file
            md5_output = cli("show file %s" % temp_md5_file)
            md5_hash = md5_output.strip().split()[0]  # Get first word (the hash)
            
            if len(md5_hash) == 32:  # Valid MD5 is 32 characters
                poap_log("INFO: Source MD5: %s" % md5_hash)
                return md5_hash
            else:
                poap_log("ERROR: Invalid MD5 format in downloaded file")
                return None

        finally:
            # Cleanup temp file
            try:
                cli("delete %s force" % temp_md5_file)
            except:
                pass

    except Exception as e:
        poap_log("ERROR: Failed to get source MD5: %s" % str(e))
        return None



def get_dst_md5(filename):
    """
    Gets MD5 hash of downloaded file
    """
    try:
        md5_output = cli("show file bootflash:%s md5sum" % filename)
        poap_log("INFO: Destination MD5: %s" % md5_output.strip())
        return md5_output.strip()
    except Exception as e:
        poap_log("ERROR: Failed to get destination MD5: %s" % str(e))
        raise


def install_firmware_image():
    """
    Attempts boot variable set with 3 retries
    """
    firmware_file = FIRMWARE_FILE
    system_image_dst = "%s" % firmware_file
    for i in range(MAX_RETRIES):
        try:
            # Install firmware
            poap_log("INFO: Setting new image as boot variable to running-configuration")
            poap_log("CLI command: config terminal ; boot nxos %s" % system_image_dst)
            cli("config terminal ; boot nxos %s" % system_image_dst) # applies to running config only
            poap_log("NOTICE: Successfully set new image as boot variable to running-configuration")

            # TODO: TEST CASE does adding non- line improve or worsen? 
            #   non-disruptive    Performs an in-service software upgrade (ISSU) to prevent the disruption of data traffic.
            #   non-interruptive  Upgrades the software without any prompts. This option skips all error and sanity checks. 
            return True
        except Exception as e:
            poap_log("WARNING: boot variable set failed: %s" % str(e))

    poap_log("ABORT: Boot variable set failed")        
    return False


def apply_config_with_retries(compliance, retry_delay=15):
    """
    Apply configuration with retries after image upgrade and reboot
    """
    for attempt in range(MAX_RETRIES):
        poap_log("INFO: Configuration application (attempt %d/%d)" % ((attempt + 1), MAX_RETRIES))
        try:
            # Try tftp copy
            if tftp_copy():
                # if tftp successful, try file copy
                if file_copy(compliance):
                    poap_log("NOTICE: Configuration applied successfully")
                    return True
                else:
                    raise Exception("ERROR: Failed to copy scheduled_config")
            else:
                raise Exception("ERROR: TFTP copy failed")

        except Exception as e:
            poap_log("ERROR: Unexpected error during config:  %s" % str(e))
            if attempt + 1 < MAX_RETRIES:
                poap_log("INFO: reattempt in %d seconds" % retry_delay)
                sleep(retry_delay)

    poap_log("ERROR: Configuration failed - max retries exceeded")
    cli("write erase")
    exit(-1)
    return False


def main():
    """
    System health retries upto MAX_RETRIES: int = 3 
    Else: Write Erase then Reload

    Verify Firmware (RENAME TO evaluate_version) retries upto MAX_RETRIES: int = 3 
    Else: 
        AKA Upgrade firmware
            `download_firmware` (move into its own call in main()
            create a function for `verify_firmware` and then call from inside `download_firmware`

        if downloaded and verified then do upgrade:
            `upgrade_firmware` (move into its own call in main()
    
    apply_config_with_retires bring code from file copy inside apply config with retires function as doesn't have enough value on its own. 
    Check if file exists rather than just tftp was successful. 

    
    """
    ##################################################
    # ***            Script Logic                  ***
    # 1. Configure log for this script
    # ** Clear log entries older than 4 executions ago
    # 2. Check firmware version - download, install and
    # reboot if necessary
    # 3. Download and apply config
    # ***                                          ***
    ##################################################

    # Configure the logging for the POAP process
    setup_logging()
    poap_log("NOTICE: Logging Setup")

    # Verify system health
    if not check_system_health():
        poap_log("ERROR: System health check failed")
        exit(-1)
    poap_log("NOTICE: System health check successful")
    
    # Upgrade firmware path: upgrade, verify, install, apply config
    if not evaluate_version_compliance():
        if upgrade_firmware():
            if install_firmware_image():
                if apply_config_with_retries(compliance = False):
                    poap_log("NOTICE: POAP completed successfully")
                    poap_log("NOTICE: Will reboot with new image and apply configuration - Exit(0)")
                    log_hdl.close()
                    exit(0)
                else:
                    poap_log("ERROR: Restarting POAP due to config error")
                    exit(-1)
            else:
                exit(-1)
        else:
            exit(-1)

    # No firmware upgrade path: transfer configuration and apply
    if not apply_config_with_retries(compliance = True):
        poap_log("ERROR: Configuration failed")
        exit(-1)
    # this behaviour is not as expected
    poap_log("NOTICE: POAP completed successfully - exit(0)")
    log_hdl.close()
    exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        poap_log("Exception: {0} {1}".format(exc_type, exc_value))
        while exc_tb is not None:
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            poap_log("Stack - File: {0} Line: {1}"
                     .format(fname, exc_tb.tb_lineno))
            exc_tb = exc_tb.tb_next
        exit(1)