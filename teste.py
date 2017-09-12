def func():
	print('func1')
	import sys
	print(sys.path)
	PATH_INSTALL = "_androwarn/*"
	sys.path.append(PATH_INSTALL)
	print(sys.path)
	from androwarn.androwarn.analysis.analysis import *
	