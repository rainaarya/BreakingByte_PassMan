from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('sign-up/', views.sign_up, name='sign-up'),
    path('sign-out/', views.sign_out, name='sign-out'),
    path('generate/', views.generate, name='generate'),
    path('my-passwords/', views.my_passwords, name='my-passwords'),
    path('add-password/', views.add_password, name='add-password'),
    path('view-edit-password', views.view_edit_password, name='view-edit-password'),
    path('share-password', views.share_password, name='share-password'),
    path('share', views.share, name='share'),
    path('two_fa', views.two_fa, name='two_fa'),
    path('sign-in', views.sign_in, name='sign-in'),
    path('rewards', views.rewards, name='rewards'),
    # path('two_fa_page', views.two_fa_page, name='two_fa_page'),
]