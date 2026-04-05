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

    

## INPUT HANDLER CLASS TEST
#***************************
def test_ihip_fail(setup_noip_fail):
    ip, file = setup_noip_fail

    in_hand = InputHandler(ip, file)
    with pytest.raises(ValueError, match = "No IP address entered"):
        in_hand.get_input_ip()

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



   
