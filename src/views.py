from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponseRedirect
import subprocess
import json, requests
import os
from django.http import JsonResponse
#from tfidf import extract
# apk hashes
# from _androwarn.androwarn.search.apk.apk import *
# models malware
from .models import Malware
import shutil
import numpy as np
import logging
from machinelearning import trainingDecisionTree
from machinelearning.export_dot_to_json import export_json

fmt = getattr(settings, 'LOG_FORMAT', None)
lvl = getattr(settings, 'LOG_LEVEL', logging.DEBUG)
logging.basicConfig(format=fmt, level=lvl)
logging.debug("Logging started on %s for %s" % (logging.root.name, logging.getLevelName(lvl)))

from myandrowarn import *

def jsonresponse(request):
    from sklearn.datasets import load_iris
    from sklearn import tree
    clf = tree.DecisionTreeClassifier()
    iris = load_iris()
    clf = clf.fit(iris.data, iris.target)
    tree.export_graphviz(clf, out_file='tree.dot')
    import tempfile
    out_file = export_json(clf, out_file=tempfile.TemporaryFile())
    out_file.close()


    #data = {"error": 0.6667, "samples": 150, "value": [50.0, 50.0, 50.0], "label": "X[2] <= 2.45", "type": "split", "children": [{"error": 0.0000, "samples": 50, "value": [50.0, 0.0, 0.0], "label": "Leaf - 1", "type": "leaf"}]};
    data = {"label": "petal length (cm) > 2.45000004768", "children": [{"label": "petal width (cm) > 1.75", "children": [{"label": "petal length (cm) > 4.85000038147", "children": [{"label": "0 of setosa, 0 of versicolor, 43 of virginica"}, {"label": "0 of setosa, 1 of versicolor, 2 of virginica"}]}, {"label": "petal length (cm) > 4.94999980927", "children": [{"label": "0 of setosa, 2 of versicolor, 4 of virginica"}, {"label": "0 of setosa, 47 of versicolor, 1 of virginica"}]}]}, {"label": "50 of setosa, 0 of versicolor, 0 of virginica"}]}
    return JsonResponse(data, safe=False)

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
                
                app_info_list = data[0] # application information
                analysis_results_list = data[1] #analysis results
                apk_file_list = data[2] # apk file
                androidmanifest_list = data[3] # androidmanifest.xml
                apis_used_list = data[4] # apis used

                # application information
                package_name_list = app_info_list['application_information'][2][1] # package_name

                #analysis results
                telephony_identifiers_leakage_list = analysis_results_list['analysis_results'][0][1]
                device_settings_harvesting_list = analysis_results_list['analysis_results'][1][1]
                location_lookup_list = analysis_results_list['analysis_results'][2][1]
                connection_interfaces_exfiltration_list = analysis_results_list['analysis_results'][3][1]
                telephony_services_abuse_list = analysis_results_list['analysis_results'][4][1]
                audio_video_eavesdropping_list = analysis_results_list['analysis_results'][5][1]
                suspicious_connection_establishment_list = analysis_results_list['analysis_results'][6][1]
                PIM_data_leakage_list = analysis_results_list['analysis_results'][7][1]
                code_execution_list = analysis_results_list['analysis_results'][8][1]

                for telephony_identifiers_leakage in telephony_identifiers_leakage_list:
                    feature_file.write('telephony_identifiers_leakage::%s\n' % telephony_identifiers_leakage)

                for device_settings_harvesting in device_settings_harvesting_list:
                    feature_file.write('device_settings_harvesting::%s\n' % device_settings_harvesting)

                for location_lookup in location_lookup_list:
                    feature_file.write('location_lookup::%s\n' % location_lookup)

                for connection_interfaces_exfiltration in connection_interfaces_exfiltration_list:
                    feature_file.write('connection_interfaces_exfiltration::%s\n' % connection_interfaces_exfiltration)

                for telephony_services_abuse in telephony_services_abuse_list:
                    feature_file.write('telephony_services_abuse::%s\n' % telephony_services_abuse)

                for audio_video_eavesdropping in audio_video_eavesdropping_list:
                    feature_file.write('audio_video_eavesdropping::%s\n' % audio_video_eavesdropping)

                for suspicious_connection_establishment in suspicious_connection_establishment_list:
                    feature_file.write('suspicious_connection_establishment::%s\n' % suspicious_connection_establishment)

                for PIM_data_leakage in PIM_data_leakage_list:
                    feature_file.write('PIM_data_leakage::%s\n' % PIM_data_leakage)

                for code_execution in code_execution_list:
                    feature_file.write('code_execution::%s\n' % code_execution)


                # androidmanifest.xml
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

                # apis used
                classes_list = apis_used_list['apis_used'][0][1] # classes list
                internal_classes_list = apis_used_list['apis_used'][1][1] # internal classes list
                external_classes_list = apis_used_list['apis_used'][2][1] # external classes list
                internal_packages_list = apis_used_list['apis_used'][3][1] # internal packages list
                external_packages_list = apis_used_list['apis_used'][4][1] # external packages list
                intents_sent_list = apis_used_list['apis_used'][5][1] # intents sent

                for intents_sent in intents_sent_list:
                    feature_file.write('intents_sent::%s\n' % intents_sent)

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


