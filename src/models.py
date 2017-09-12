# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

from django.utils import timezone
#https://medium.com/@tk512/upgrading-postgresql-from-9-3-to-9-4-on-ubuntu-14-04-lts-2b4ddcd26535
from django.contrib.postgres.fields import JSONField

# Create your models here.
class MalwareManager(models.Manager):
    def create_malware(self, apk):
        malware = self.create(
            application_name=apk['application_name'],
            application_version=apk['application_version'],
            package_name = apk['package_name'],
            description = apk['description'],
            telephony_identifiers_leakage = apk['telephony_identifiers_leakage'],
            device_settings_harvesting = apk['device_settings_harvesting'],
            location_lookup = apk['location_lookup'],
            connection_interfaces_exfiltration = apk['connection_interfaces_exfiltration'],
            telephony_services_abuse = apk['telephony_services_abuse'], 	
            audio_video_eavesdropping = apk['audio_video_eavesdropping'],
            suspicious_connection_establishment = apk['suspicious_connection_establishment'],
            pim_data_leakage = apk['PIM_data_leakage'],	
            code_execution = apk['code_execution'],
            file_name = apk['file_name'],
            file_list = apk['file_list'],
            certificate_information = apk['certificate_information'],
            md5 = apk['md5'],
            sha1 = apk['sha1'],
            sha256 = apk['sha256'],
            main_activity =  apk['main_activity'],
            activities =  apk['activities'],
            permissions = apk['permissions'],
            features = apk['features'],
            classes_list = apk['classes_list'],
            internal_classes_list = apk['internal_classes_list'],
            external_classes_list = apk['external_classes_list'],
            internal_packages_list = apk['internal_packages_list'],
            external_packages_list = apk['external_packages_list'],
            intents_sent = apk['intents_sent'],
            created_date = timezone.now(),
            virustotal_report_link = apk['virustotal_report_link'],
            json_data = apk['json_data']
            )
        # do something with the book
        return malware
   

class Malware(models.Model):
    ### APPLICATION INFORMATION
    application_name = models.CharField(max_length=200)
    application_version = models.CharField(max_length=200, null=True)
    package_name = models.CharField(max_length=200, null = True)
    description = models.TextField(null=True)
    
    ### ANALYSIS RESULTS
    telephony_identifiers_leakage = models.TextField(null=True)
    device_settings_harvesting = models.TextField(null=True)	
    location_lookup = models.TextField(null=True)				
    connection_interfaces_exfiltration = models.TextField(null=True)	
    telephony_services_abuse = models.TextField(null=True)		
    audio_video_eavesdropping = models.TextField(null=True)		
    suspicious_connection_establishment = models.TextField(null=True)	
    pim_data_leakage = models.TextField(null=True)			
    code_execution = models.TextField(null=True)
    
    ### APK FILE 
    file_name = models.CharField(max_length=200, null=True)
    file_list = models.TextField(null=True)
    certificate_information = models.TextField(null=True)
    
    ### FINGERPRINT
    md5 = models.CharField(max_length=32, null=True)
    sha1 = models.CharField(max_length=40, null=True)
    sha256 = models.CharField(max_length=64, null=True)
    
    ### ANDROIDMANIFEST.XML
    main_activity =  models.TextField(null=True)
    activities =  models.TextField(null=True)
    permissions = models.TextField(null=True)
    features =  models.TextField(null=True)
    
    ### APIS USED
    classes_list = models.TextField(null=True)
    internal_classes_list = models.TextField(null=True)
    external_classes_list = models.TextField(null=True)
    internal_packages_list = models.TextField(null=True)
    external_packages_list = models.TextField(null=True)
    intents_sent = models.TextField(null=True)
    
    ### ADDITIONAL
    created_date = models.DateTimeField(default=timezone.now)
    virustotal_report_link = models.TextField(null=True)
    json_data = JSONField(default={})
    
    #def __str__(self):
    #    return self
        
    objects = MalwareManager()

class MyDecisionTreeModel(models.Model):
    title = models.CharField(max_length=50)
    description = models.TextField()

    def __unicode__(self):
        return self.title

    class Meta(object):
        verbose_name = 'My Decision Tree Model'
        verbose_name_plural = 'My Decision Tree Models'

