from importlib import import_module
from inspect import getmembers, isclass

from netattacker.attacker import AttackerBaseClass

base_classes = ['AttackerBaseClass', 'ScannerBaseClass']

def grab(attack_module:str, *args, **kwargs):
	try:
		# Need to figure out a better way
		if ('modules' not in attack_module):
			module_name = "netattacker.modules." + attack_module

		# for example poisoners.arp, or poisoners.apr.ArpPoisoner is passed
		if (1 == attack_module.count('.')):
			imported_module = import_module(module_name)
			for name, obj in getmembers(imported_module, isclass):
				if (issubclass(obj, AttackerBaseClass) and name not in base_classes):
					class_name = name
					break

		if (2 <= attack_module.count('.')):
			module_name, class_name = attack_module.rsplit(".", 1)
			imported_module = import_module(module_name)

		attack_class = getattr(imported_module, class_name)

		instance = attack_class(*args, **kwargs)

	except (AttributeError, AssertionError, ImportError):
		raise ImportError('[#] {} is not part of any submodules!'.format(attack_module))

	else:
		if not issubclass(attack_class, AttackerBaseClass):
			raise ImportError("[#] The project currently doesn't have {}, but you are welcome to send in the request for it!".format(attack_class))

	return instance
