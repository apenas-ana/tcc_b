from django.conf.urls import url
from .views import index, analise, bulkload, tsnejs, search, decisionTreeViewer

urlpatterns = [
    url(r'^$', index, name ="index"),
    url(r'^analise/', analise, name ="analise"),
    url(r'^bulkload/', bulkload, name ="bulkload"),
    url(r'^tsnejs/', tsnejs, name ="tsnejs"),
    url(r'^search/', search, name="search"),
    url(r'^decisionTreeViewer/', decisionTreeViewer, name="decisionTreeViewer"),
]