from src.attacker import Attacker

from importlib import import_module

def grab(scr_name, *args, **kwargs):
	try:
		#if 'modules.' in scr_name:
		if ('.' in scr_name):
			module_name, class_name = scr_name.rsplit(".", 1)

		attack_module = import_module('.' + module_name, package='modules')

		attack_class = getattr(attack_module, class_name)

		instance = attack_class(*args, **kwargs)

	except (AttributeError, AssertionError, ModuleNotFoundError):
		raise ImportError('{} is not part of any submodules!'.format(scr_name))

	else:
		if not issubclass(attack_class, Attacker):
			raise ImportError("We currently don't have {}, but you are welcome to send in the request for it!".format(attack_class))

	return instance