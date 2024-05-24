"""
URL configuration for gift_card_django project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include  # new
from . import views  # new

urlpatterns = [
    path("admin/", admin.site.urls),
    path("__reload__/", include("django_browser_reload.urls")),  # new
    path("", views.home, name="home"),  # new
    path("makecontracts/", views.make_contracts, name="make_contracts"),
    path("lock/", views.lock, name="lock"),
    path("lock/sign/", views.lock_sign, name="lock_sign"),
    path("lock/success/", views.lock_success, name="lock_success"),
    path("unlock/", views.unlock, name="unlock"),
    path("unlock/sign/", views.unlock_sign, name="unlock_sign"),
    path("unlock/success/", views.unlock_success, name="unlock_success"),
]
