#-------------------------------------------------------------------------
# 
# Copyright Microsoft Open Technologies, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http: *www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
# PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
# See the Apache License, Version 2.0 for the specific language
# governing permissions and limitations under the License.
#
#--------------------------------------------------------------------------

class MemoryCache(object):
    
    def __init__(self):
        self._entries = []

    def remove(self, entries, callback):

        updated_entries = [entry for entry in self._entries if entry not in entries]
        self._entries = updated_entries
        callback(None)

    def add(self, entries, callback):

        for entry in entries:
            if entry not in self._entries:
                self._entries.append(entry)

        callback(None, True)

    def find(self, query, callback):
        results = []
        for entry in self._entries:
            comp = [True for item in entry.items() if item in query.items()]
            if len(comp) == len(query):
                results.append(entry)
        callback(None, results)
