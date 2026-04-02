import subprocess 
import xml.etree.ElementTree as ET

##subprocess.run(["open", "-a", "Microsoft Word"])

tree = ET.parse('scan.xml')
root = tree.getroot()

#Add Class to hold variables & methods
class PortReport
    
    def __init__(self):
        
        self.__protocol
        self.__portid
        self.__state
        self.__reason
        self.__reason_ttl
        self.__name 
        self.__servicefp
        self.__method
        self.__conf

    def parse_report(self) -> None:
        for port in root.iter('port'):
            protocol = port.get('protocol')
            port_id = port.get('portid')
            state = port.find('state').get('state')
            reason = port.find('state').get('reason')
            reason_ttl = port.find('state').get('reason_ttl')
            name = port.find('service').get('name')
            servicefp = port.find('service').get('servicefp')
            method = port.find('service').get('method')
            conf = port.find('service').get('conf')
            #print(protocol, port_id)
                


