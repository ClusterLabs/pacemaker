# Copyright (C) 2008 Dejan Muhamedagic <dmuhamedagic@suse.de>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

import time
from singletonmixin import Singleton

class WCache(Singleton):
    "Cache stuff. A naive implementation."
    def __init__(self):
        self.lists = {}
        self.stamp = time.time()
        self.max_cache_age = 600 # seconds
    def is_cached(self,name):
        if time.time() - self.stamp > self.max_cache_age:
            self.stamp = time.time()
            self.clear()
        return name in self.lists
    def store(self,name,lst):
        self.lists[name] = lst
        return lst
    def retrieve(self,name):
        if self.is_cached(name):
            return self.lists[name]
        else:
            return None
    def clear(self):
        self.lists = {}

# vim:ts=4:sw=4:et:
