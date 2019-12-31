from src.attacker import Attacker
from importlib import import_module
from pathlib import Path
import pkgutil
import os
import sys
import inspect


for (_, name, _) in pkgutil.iter_modules([os.path.dirname(__file__)]):
		imported_module = import_module('.' + name, package=__name__)

		class_name = list(filter(lambda x: x != 'Attacker' and not x.startswith('__'), dir(imported_module)))

		for i in dir(imported_module):
			attribute = getattr(imported_module, i)

			if inspect.isclass(attribute) and issubclass(attribute, Attacker):
				setattr(sys.modules[__name__], name, attribute)