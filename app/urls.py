from django.contrib import admin
from django.urls import path
from .views import index,learning
urlpatterns = [
    path("",index,name="index"),
    path("learning",learning,name="learning")


]