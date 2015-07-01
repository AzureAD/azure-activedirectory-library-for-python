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

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET
    
from . import constants

XPATH_PATH_TEMPLATE = '*[local-name() = \'LOCAL_NAME\' and namespace-uri() = \'NAMESPACE\']'

def expand_Q_names(xpath):

    namespaces = constants.XmlNamespaces.namespaces
    path_parts = xpath.split('/')
    for index, part in enumerate(path_parts):
        if part.find(":") != -1:
            q_parts = part.split(':')
            if len(q_parts) != 2:
                raise IndexError("Unable to parse XPath string: {0} with QName: {1}".format(xpath, part))

            expanded_path = XPATH_PATH_TEMPLATE.replace('LOCAL_NAME', q_parts[1])
            expanded_path = expanded_path.replace('NAMESPACE', namespaces[q_parts[0]])
            path_parts[index] = expanded_path

    return '/'.join(path_parts)

def xpath_find(dom, xpath):
    return dom.findall(xpath, constants.XmlNamespaces.namespaces)

def serialize_node_children(node):

    doc = ""
    for child in node.iter():
        if is_element_node(child):
            estring = ET.tostring(child)
            doc += estring if isinstance(estring, str) else estring.decode()

    return doc if doc else None

def is_element_node(node):
    return hasattr(node, 'tag')

def find_element_text(node):

    for child in node.iter():
        if child.text:
            return child.text
