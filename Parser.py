import subprocess 
import xml.etree.ElementTree as ET

tree = ET.parse('scan.xml')
root = tree.getroot()

for port in root.iter('port'):
    protocol = port.get('protocol')
    port_id = port.get('portid')
    print(protocol, port_id)


##subprocess.run(["open", "-a", "Microsoft Word"])

