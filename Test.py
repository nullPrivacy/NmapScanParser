
import subprocess 
import xml.etree.ElementTree as ET

tree = ET.parse('scan.xml')
root = tree.getroot()

def explore(element, depth=0):
    print(" " * depth + f"[{depth}]<{element.tag}> attrs: {list(element.attrib.keys())}")
    for child in element:
        explore(child, depth + 1)

explore(root)
