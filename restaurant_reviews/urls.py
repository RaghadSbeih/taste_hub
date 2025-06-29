from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    #auth urls
    
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    
    #admin urls

    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/restaurant/add/', views.add_restaurant, name='add_restaurant'),
    path('admin/restaurant/edit/<int:restaurant_id>/', views.edit_restaurant, name='edit_restaurant'),
    path('admin/restaurant/delete/<int:restaurant_id>/', views.delete_restaurant, name='delete_restaurant'),
    path('admin/review/delete/<int:review_id>/', views.delete_review, name='delete_review'),

    #user urls

    path('restaurant/<int:restaurant_id>/', views.restaurant_detail, name='restaurant_detail'),
    path('review/edit/<int:review_id>/', views.edit_review, name='edit_review'),
    path('review/delete/<int:review_id>/', views.delete_review_user, name='delete_review_user'),
]