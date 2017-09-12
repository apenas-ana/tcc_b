from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponseRedirect
import subprocess
import json, requests
import os
#from tfidf import extract
# apk hashes
# from _androwarn.androwarn.search.apk.apk import *
# models malware
from .models import Malware
import shutil
import numpy as np
import logging

"""
bashCommand = "file -z %s" % uploaded_file_url      
logging.info(bashCommand)
process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
output, error = process.communicate()
logging.info(output)
"""

fmt = getattr(settings, 'LOG_FORMAT', None)
lvl = getattr(settings, 'LOG_LEVEL', logging.DEBUG)

logging.basicConfig(format=fmt, level=lvl)
logging.debug("Logging started on %s for %s" % (logging.root.name, logging.getLevelName(lvl)))

from myandrowarn import *

def index(request):
	if request.method == 'POST' and request.FILES['files'] and len(request.FILES.getlist('files')) > 0:
		logging.info('Qtd de arquivos: %s' % len(request.FILES.getlist('files'))) 
		parameters = {}
		fs = FileSystemStorage()
		log_ok = open(os.path.join(settings.BASE_DIR, 'logs/log_success.txt'), 'w')
		log_notok = open(os.path.join(settings.BASE_DIR, 'logs/log_error.txt'), 'w')

        for file in request.FILES.getlist('files'):
            filename = fs.save(file.name, file)
            uploaded_file_url = fs.url(filename)
            uploaded_file_url = settings.BASE_DIR + uploaded_file_url
            parameters['input'] = uploaded_file_url

            try:
                data, html = call_androwarn(parameters)
                log_ok.write(file.name + '\n')

                feature_file = open(os.path.join(settings.BASE_DIR, 'features', file.name), 'wb')
                print(os.path.join(settings.BASE_DIR, 'features', file.name))
                for item in data[1]:
                    if len(data[1][item]) > 0:
                        for feature in data[1][item]: # for itens in analysis_results (telephony_identifiers_leakage, device_settings_harvesting, etc...)
                            if len(feature[1]) > 0:
                                for valores in feature[1]: # feature[0] = label, feature[1] = valor/valores da feature
                                    feature_file.write("%s" % feature[0] + '::'+valores+'\n')

                app_info_list = data[0] # application information
                androidmanifest_list = data[3] # androidmanifest.xml

                package_name_list = app_info_list['application_information'][2][1] # package_name
                main_activity_list = androidmanifest_list['androidmanifest.xml'][0][1] # main_activity
                activities_list = androidmanifest_list['androidmanifest.xml'][1][1] # activities
                receivers_list = androidmanifest_list['androidmanifest.xml'][2][1] # receivers
                providers_list = androidmanifest_list['androidmanifest.xml'][3][1] # providers
                permissions_list = androidmanifest_list['androidmanifest.xml'][4][1] # permissions
                features_list = androidmanifest_list['androidmanifest.xml'][5][1] # features
                libraries_list = androidmanifest_list['androidmanifest.xml'][6][1] # libraries

                for main_activity in main_activity_list:
                    feature_file.write('main_activity::%s\n' % main_activity)

                for activity in activities_list:
                    feature_file.write('activity::%s\n' % activity)

                for receiver in receivers_list:
                    feature_file.write('receiver::%s\n' % receiver)

                for provider in providers_list:
                    feature_file.write('provider::%s\n' % provider)

                for permission in permissions_list:
                    feature_file.write('permission::%s\n' % permission)

                for feature in features_list:
                    feature_file.write('feature::%s\n' % feature)

                for library in libraries_list:
                    feature_file.write('library::%s\n' % library)

                feature_file.close()

            except:
                log_notok.write(file.name + '\n')
                print 'not ok'
        #log_ok.close()
        #log_notok.close()
	return render(request, 'index.html')

def home(request):
    documents = Document.objects.all()
    return render(request, 'core/home.html', { 'documents': documents })


def simple_upload(request):
    if request.method == 'POST' and request.FILES['myfile']:
        myfile = request.FILES['myfile']
        fs = FileSystemStorage()
        filename = fs.save(myfile.name, myfile)
        uploaded_file_url = fs.url(filename)
        return render(request, 'core/simple_upload.html', {
            'uploaded_file_url': uploaded_file_url
        })
    return render(request, 'core/simple_upload.html')


def model_form_upload(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('home')
    else:
        form = DocumentForm()
        print(form.as_p)
    return render(request, 'core/model_form_upload.html', {
        'form': form
    })

def analise(request):
    mal = Malware.objects.filter(id=1)
    #print mal[0].file_name.encode('ascii','ignore')
    #print mal[0].json_data
    
    jsonToDict = json.JSONDecoder().decode(mal[0].json_data);
    
    if request.method == 'POST' and request.FILES['files']:
        files = request.FILES['files']
        fs = FileSystemStorage()
        filename = fs.save(files.name, files)
        uploaded_file_url = fs.url(filename)
        
        # Virustotal API
        json_response = virustotal('tcc/'+uploaded_file_url)
    
        #os.system('python androwarn.py -i '+ 'tcc/'+uploaded_file_url +' -r html -v 3')
        parameters = {}
        parameters['input'] = 'tcc/'+uploaded_file_url
        data, html = call_androwarn(parameters)
    
        ### CALL FINGERPRINT FUNCTION HERE
        
        fingerprint(parameters['input'], data, json_response)
        
        #extract('this', html)
        
        html = 'Report/' + html
        
        tam = []
        report = []
        for count in range(0, len(data)):
            tam.append(count)
            for item in data[count]:
                #print(str(item))
                report.append(item)
        
        return render(request, 'analise.html', {
            'tam': tam, 'report': report, 'url': json_response['permalink'], 'html': html,
        })
    return render(request, 'index.html')
    
def report_html(request, year):
    return render(request, '/home/ubuntu/workspace/workspace/'+year+'.html', {})


def bulkload(request):
    fs = FileSystemStorage()
    parameters = {}
    count = 1
    
    for f in request.FILES.getlist('files'):
        print count
        sucess_path = settings.MEDIA_ROOT + '/drebin-1/sucesso/' + f.name
        error_path = settings.MEDIA_ROOT + '/drebin-1/erro/' + f.name
        filename = fs.save(sucess_path, f)
        parameters['input'] = sucess_path
        print sucess_path
        print error_path
        try:
            data, html = call_androwarn(parameters)
            # Virustotal API
            json_response = virustotal(parameters['input'])
            ### CALL FINGERPRINT FUNCTION HERE
            fingerprint(parameters['input'], data, json_response)
        except:
            #print('Erro ao analisar apk com Androwarn')
            shutil.move(sucess_path, error_path)
        count+=1
        
    return render(request, 'bulkload.html')


def search(request):
    if request.method == 'POST':
        print 'post' 
        apkEscolhido = request.POST.get("name_field", None)
        apkDados = json.JSONDecoder().decode(Malware.objects.filter(file_name=apkEscolhido)[0].json_data)
        print
        return render(request, 'malware_details.html', {'apkDados': apkDados,} )

    
    
    mal = Malware.objects.all()
    
    jsonToDict = json.JSONDecoder().decode(mal[0].json_data);
    
    fields = []
    values = []
    
    for key, value in jsonToDict.items():
        fields.append(key)
        values.append(value)
    
    return render(request, 'malware_list.html', {'malwares': mal,} )

    

def fingerprint(filename, filename_data, virustotal_report):
    hashes = grab_apk_file_hashes(filename)
        
    _md5 = hashes[0].split("MD5: ")[1]
    _sha1 = hashes[1].split("SHA-1: ")[1]
    _sha256 = hashes[2].split("SHA-256: ")[1]
    
    your_filters = {
    'md5__exact': _md5,
    'sha1__exact': _sha1,
    'sha256': _sha256,
    }
    
    if Malware.objects.filter(**your_filters):
        print("There is at least one Entry that matchs with the filters")
        path = os.path.join(settings.PROJECT_PATH, 'media')
        dir = os.listdir(path)
        for file in dir:
            if file == filename:
                print os.path.join(path, file)
                os.remove(os.path.join(path, file))
    else:
        new_malware = {}
    
        for item in filename_data:
            for ( key, value ) in item.items():
                for v in value:
                    if v[0] != 'fingerprint':
                        new_malware[v[0]] = v[1]
            
        new_malware['md5'] = _md5
        new_malware['sha1'] = _sha1
        new_malware['sha256'] = _sha256
        new_malware['virustotal_report_link'] = virustotal_report
        new_malware['json_data'] = json.dumps(new_malware)
        
        print new_malware
            
        malware = Malware.objects.create_malware(new_malware)
        malware.save()
    
    return

        
        
        
### VIRUSTOTAL API
def virustotal(file_url):
    params = {'apikey': '3301dbee11a346a223d99813bd46446328980503676925165831740f0f06d374'}
    files = {'file': (file_url, open(file_url, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    return json_response

def tsnejs(request):
    labels = []
    
    with open("/home/ubuntu/workspace/tcc/featuresdv.npy", "rb") as npy:
        a = np.load(npy).tolist()
    
    """
    with open('/home/ubuntu/workspace/labelsfile.txt', 'r') as f:
        for item in f:
            labels.append(item)
    
    print(len(labels))
    """
    
    return render(request, 'tsne.html')

def decisionTreeViewer(request):
	return render(request, 'decisionTreeViewer.html')


