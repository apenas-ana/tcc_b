# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from .models import MyDecisionTreeModel

# admin.site.register(MyDecisionTreeModel)


from django.contrib import admin

from django.contrib.auth.models import User

from django.contrib.admin import AdminSite

from .views import index

class MyAdminSite(AdminSite):
    def get_urls(self):
        from django.conf.urls import url
        urls = super(MyAdminSite, self).get_urls()
        # Note that custom urls get pushed to the list (not appended)
        # This doesn't work with urls += ...
        urls = [
            url(r'^newTree/$', self.admin_view(index), name="newTree")
        ] + urls
        return urls

admin_site = MyAdminSite()

class MyDecisionTreeModelAdmin(admin.ModelAdmin):
    fieldsets = [
        (None,               {'fields': ['title']}),
        ('Date information', {'fields': ['description'], 'classes': ['collapse']}),
    ]
    
    list_display = ('title', 'description')
    list_filter = ['title']
    search_fields = ['title']
    #date_hierarchy = 'title'
    
    
admin_site.register(MyDecisionTreeModel, MyDecisionTreeModelAdmin)