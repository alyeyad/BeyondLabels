import logging
logging.basicConfig(level=logging.DEBUG)
import json

from webtest import TestApp #Docs: http://webtest.pythonpaste.org/en/latest/
from auth import simpleauth


app = TestApp(simpleauth.app)

def test_sql_injection():
	
	pass


def test_create_user():
	pass

def test_update_user():
	pass

def test_delete_user():
	pass



def test_create_group():
	pass

def test_update_group():
	pass

def test_delete_group():
	pass

