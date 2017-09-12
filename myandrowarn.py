#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

# Global imports
import os, sys, re, logging, json

# OptionParser imports
from optparse import OptionParser

# Androguard imports
PATH_INSTALL = "./androguard/"
sys.path.append(PATH_INSTALL)

# Androwarn modules import
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)
from androwarn.core.core import *
from androwarn.search.search import *
from androwarn.util.util import *
from androwarn.report.report import *
from androwarn.analysis.analysis import *

from django.conf import settings
FILETXT_DIR = os.path.join(settings.BASE_DIR, 'Report/features_txt/')


import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt

# Logger definition
log = logging.getLogger('log')
log.setLevel(logging.ERROR)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)

# Options definition
option_0 = { 'name' : ('-i', '--input'), 'help' : 'APK file to analyze', 'nargs' : 1 }
option_1 = { 'name' : ('-v', '--verbose'), 'help' : 'Verbosity level { 1-3 } (ESSENTIAL, ADVANCED, EXPERT)', 'nargs' : 1 }
option_2 = { 'name' : ('-r', '--report'), 'help' : 'Report type { txt, html }', 'nargs' : 1 }
option_3 = { 'name' : ('-d', '--display-report'), 'help' : 'Display analysis results to stdout', 'action' : 'count' }
option_4 = { 'name' : ('-L', '--log-level'), 'help' : 'Log level { DEBUG, INFO, WARN, ERROR, CRITICAL }', 'nargs' : 1 }
option_5 = { 'name' : ('-n', '--no-connection'), 'help' : 'Disable online lookups on Google Play', 'action' : 'count'}

options = [option_0, option_1, option_2, option_3, option_4, option_5]

def main(options) :

			
	if (options['input'] != None) :
		
		# Log_Level
		if options['log_level'] != None :
			try :
				log.setLevel(options['log_level'])
			except :
				print("Please specify a valid log level")
		
		# Verbose
		if (options['verbose'] != None) and (options['verbose'] in VERBOSE_LEVEL) :
			verbosity = options['verbose']
		else :
			print("Please specify a valid verbose level")
		
		# Report Type	
		if (options['report'] != None) and (options['report'] in REPORT_TYPE) :
			report_wanted = True
			report = options['report']
		elif (options['report'] == None) and (options['display_report'] != None) :
			report_wanted = False
		else :
			print("Please specify a valid report type")

		# Online Lookups enabled	
		no_connection = {True : CONNECTION_DISABLED, False : CONNECTION_ENABLED}[options['no_connection'] != None] 

		# Input	
		APK_FILE = options['input']


		a, d, x = AnalyzeAPK(APK_FILE)

		package_name = grab_application_package_name(a)
		
		data = perform_analysis(APK_FILE, a, d, x, no_connection)
		
		""" GRÁFICO 
		listinha = []
		sum = 0
		labels = ()
		sizes = []
		
		
		for item in data[1]:
			#print(item)
			if len(data[1][item]) > 0:
				for it2 in data[1][item]:
					if len(it2[1]) > 0:
						tupla = (it2[0], len(it2[1]))
						sizes.append(len(it2[1]))
						sum += len(it2[1])
						labels = labels + (traduz_label(it2[0]), )
						for str in it2[1]:
							listinha.append(str)
		
	
		colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', 'green', 'purple', 'pink', 'white', 'grey']
		fig1, ax1 = plt.subplots(figsize=(11, 5))
		#patches, texts = ax1.pie(sizes, autopct='%.2f', shadow=True, startangle=90)
		
		#ax1.legend(labels,  bbox_to_anchor=(1.1,1.025), loc='upper right')
		ax1.pie(sizes, colors=colors, labels=labels, autopct='%1.1f%%', shadow=True, startangle=90)
		#plt.legend(, loc="lower left")
		ax1.axis('equal')
		
				
		plt.savefig("/home/ubuntu/workspace/upload/core/static/fig.png")
		"""

		if (options['display_report'] != None) :
			# Brace yourself, a massive dump is coming
			dump_analysis_results(data,sys.stdout) 
	
		if report_wanted :
			html = generate_report(package_name, data, verbosity, report)
		
		#write_file(listinha, html)
    	return data, html

def traduz_label(label):
    switcher = {
        'telephony_identifiers_leakage': 'Vazamento de identificadores de telefonia',
        'device_settings_harvesting': 'Coleta de configuracoes do dispositivo',
        'location_lookup': 'Pesquisa de localizacao',
        'connection_interfaces_exfiltration': 'Exfiltracao de interface de conexao',
        'telephony_services_abuse': 'Abuso de servicos de telefonia',
        'audio_video_eavesdropping': 'Espionagem de audio e video',
        'suspicious_connection_establishment': 'Estabelecimento de conexao suspeita',
        'PIM_data_leakage': 'Vazamento de dados PIM',
        'code_execution': 'Execucao de codigo',
    }
    return switcher.get(label, '')
    
def write_file(data, output_file) :
	output_file = "%s%s.txt" % (FILETXT_DIR, output_file)
	
	with open(output_file, 'w') as f_out :
		for str in data:
			f_out.write("%s\n" % str)
	f_out.close()
		

def call_androwarn(parameters) :

	comandos = {}
	comandos['input'] = parameters['input']
	comandos['verbose'] = '3'
	comandos['report'] = 'html'
	comandos['log_level'] = None
	comandos['display_report'] = None
	comandos['no_connection'] = None
	data, html = main(comandos)
	return data, html

if __name__ == "__main__":
	comandos = {}
	comandos['input'] = 'plantsvsan.apk'
	comandos['verbose'] = '3'
	comandos['report'] = 'html'
	comandos['log_level'] = None
	comandos['display_report'] = None
	comandos['no_connection'] = None
	data, html = main(comandos)