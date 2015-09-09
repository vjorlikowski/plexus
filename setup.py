#!/usr/bin/env python

import glob
import distutils.log

from distutils.core import setup
from distutils.command.install import install
from errno import EEXIST
from plexus import __version__

package_name = 'plexus'
default_base_directory = '/opt/' + package_name
default_conf_directory = '/etc/' + package_name
default_state_directory = '/var/lib/' + package_name
default_log_directory =  '/var/log/' + package_name

setup(name = package_name,
      version = __version__,
      packages = [package_name],
      data_files = [(default_conf_directory, ['sample_configuration/ryu.conf', 'sample_configuration/log.conf']),
                    (default_state_directory, []),
                    (default_log_directory, [])]
)
