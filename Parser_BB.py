#James McKinley
#NmapParser Project Black Box Test v0.1.0

import Parser
import pytest
from Parser import InputHandler, Scanner, Parser, Reporter

@pytest.fixture
def setup_a_pass():
    ip =  "127.0.0.1"
    file = "GoodFileName"
    return ip, file

@pytest.fixture
def setup_a_fail():
    ip = "NotGoodIP"
    file = "/@"
    return ip, file

@pytest.fixture
def setup_ip_fail():
    ip = "NotGoodIP"
    file = "GoodFileName"
    return ip, file

@pytest.fixture
def setup_fn_fail():
    ip =  "127.0.0.1"
    file = "/@"
    return ip, file

@pytest.fixture
def setup_noip_fail():
    ip =  ""
    file = "GoodFileName"
    return ip, file
'''
@pytest.fixture
def setup_fake():
    return "127.0.0.1"
'''

## INPUT HANDLER CLASS TEST
#***************************
def test_ihip_pass(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: "127.0.0.1")
    obj = InputHandler()
    
    result = obj.get_input_ip()
    assert result  == "127.0.0.1"
    
    ''' 
    #Achieves the same input as the lambda (more explicit) as 2nd patch arg

    def setup_fake(self)->str:
        return "127.0.0.1"

    '''

def test_ihip_empty(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: None)
    obj = InputHandler()
    
    with pytest.raises(ValueError, match = "No IP address entered"):
        _ = obj.get_input_ip()
  
def test_ihfn_pass(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: "GoodFileName")
    obj = InputHandler()
    
    result = obj.get_input_file()
    assert result  == "GoodFileName"

def test_ihfn_empty(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: None)
    obj = InputHandler()
    
    with pytest.raises(ValueError, match= "No file name entered"):
        _= obj.get_input_file()        
         
    
## SCANNER CLASS TEST
#*********************

#Subprocess returns 0 for success/!=0 when failure
def test_scn_pass(setup_a_pass):
    ip_p, fn_p = setup_a_pass
    pass_condition = 0
    
    test_scanner = Scanner(ip_p, fn_p)
    assert test_scanner.scan_xml() == pass_condition

def test_scn_fail(setup_a_fail):
    ip_f, fn_f = setup_a_fail
    fail_condition = 1
    
    test_scanner = Scanner(ip_f, fn_f)
    assert test_scanner.scan_xml() == fail_condition
    
def test_scn_ip_fail(setup_ip_fail):
    ip_f, fn_p = setup_ip_fail
    
    test_scanner = Scanner(ip_f, fn_p)
    with pytest.raises(ValueError, match = "No Hosts Available"):
        test_scanner.scan_xml()

def test_scn_fn_fail(setup_fn_fail):
    ip_p, fn_f = setup_fn_fail
    fail_condition = 1
    
    test_scanner = Scanner(ip_p, fn_f)
    assert test_scanner.scan_xml() == fail_condition



   
