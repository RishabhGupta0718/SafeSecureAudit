from django.contrib import admin
from django.urls import path
from .views import index,learning,termsandcondition,Allaboutbugbounty
urlpatterns = [
    path("",index,name="index"),
    path("learning",learning,name="learning"),
    path("termsandcondition",termsandcondition,name="termsandcondition"),
    path("Allaboutbugbounty",Allaboutbugbounty,name="Allaboutbugbounty")


]