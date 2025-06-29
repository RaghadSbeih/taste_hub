from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.shortcuts import redirect
from .models import User, Restaurant, Review
import bcrypt
from django.contrib.auth import authenticate, login
from django.utils import timezone
from datetime import timedelta
from django.core.files.storage import FileSystemStorage
from django.db.models import Avg
from django.http import HttpResponse, JsonResponse


# Create your views here.
def get_logged_in_user(request):
    user_id=request.session.get('user_id')
    if user_id:
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None
    return None
    
def index(request):
    if 'user_id' not in request.session:
        return redirect('/login')
    search_query = request.GET.get('q', '').strip()
    city_filter = request.GET.get('city', '').strip()
    cuisine_filter = request.GET.get('cuisine_type', '').strip()
    restaurants = Restaurant.objects.all()
    if search_query:
        restaurants = restaurants.filter(name__icontains=search_query)
    if city_filter:
        restaurants = restaurants.filter(city__iexact=city_filter)
    if cuisine_filter:
        restaurants = restaurants.filter(cuisine_type__iexact=cuisine_filter)
    cities = Restaurant.objects.values_list('city', flat=True).distinct()
    cuisines = Restaurant.objects.values_list('cuisine_type', flat=True).distinct()
    context = {
        'restaurants': restaurants,
        'search_query': search_query,
        'city_filter': city_filter,
        'cuisine_filter': cuisine_filter,
        'cities': cities,
        'cuisines': cuisines,
    }
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return render(request, 'index.html', context | {'ajax_only': True})
    return render(request, 'index.html', context)

def register(request):
    print(request.POST)
    if request.method == "POST":
        errors = User.objects.registration_validator(request.POST)
        print(errors)
        if errors:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/register')
        
        
        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        

        user = User.objects.create(
            first_name=request.POST['first_name'],
            last_name=request.POST['last_name'],
            email=request.POST['email'],
            password=pw_hash
        )
        print(user)
        
        request.session['user_id'] = user.id
        return redirect('/')
    return render(request, 'register.html')

def login(request):
    if request.method == "POST":
        login_field = request.POST.get('username') or request.POST.get('email')
        password = request.POST.get('password')
        user = User.objects.filter(email=login_field).first()
        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            request.session['user_id'] = user.id
            if user.role == 'admin':
                return redirect('restaurant_reviews:admin_dashboard')
            else:
                return redirect('restaurant_reviews:index')
        else:
            messages.error(request, 'Invalid credentials')
            return redirect('/login')
    return render(request, 'login.html')

def logout(request):
    request.session.clear()
    return redirect('/')

def admin_dashboard(request):
    if not request.session.get('user_id'):
        return redirect('restaurant_reviews:login')
    user = User.objects.filter(id=request.session['user_id']).first()
    if not user or user.role != 'admin':
        return redirect('restaurant_reviews:login')

    total_restaurants = Restaurant.objects.count()
    total_reviews = Review.objects.count()
    week_ago = timezone.now() - timedelta(days=7)
    new_reviews = Review.objects.filter(created_at__gte=week_ago).count()
    restaurants = Restaurant.objects.all()
    reviews = Review.objects.select_related('user', 'restaurant').order_by('-created_at')[:5]

    context = {
        'total_restaurants': total_restaurants,
        'total_reviews': total_reviews,
        'new_reviews': new_reviews,
        'restaurants': restaurants,
        'reviews': reviews,
    }
    return render(request, 'admin_dashboard.html', context)

def add_restaurant(request):
    user = get_logged_in_user(request)
    if not user or user.role != 'admin':
        return redirect('restaurant_reviews:login')

    CUISINE_CHOICES = [
        'Italian', 'Japanese', 'American', 'Mexican', 'Chinese', 'Indian', 'French', 'Mediterranean', 'Other'
    ]
    
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        address = request.POST.get('address', '').strip()
        city = request.POST.get('city', '').strip()
        contact_number = request.POST.get('contact_number', '').strip()
        cuisine_type = request.POST.get('cuisine_type', '').strip()
        description = request.POST.get('description', '').strip()
        image = request.FILES.get('image')
        errors = Restaurant.objects.restaurant_validator(request.POST)
        if errors:
            for err in errors.values():
                messages.error(request, err)
            return render(request, 'add_restaurant.html', {'cuisine_choices': CUISINE_CHOICES})
        Restaurant.objects.create(
            name=name,
            address=address,
            city=city,
            cuisine_type=cuisine_type,
            description=description,
            image=image
        )
        messages.success(request, 'Restaurant added successfully!')
        return redirect('restaurant_reviews:admin_dashboard')
    return render(request, 'add_restaurant.html', {'cuisine_choices': CUISINE_CHOICES})

def edit_restaurant(request, restaurant_id):
    user = get_logged_in_user(request)
    if not user or user.role != 'admin':
        return redirect('restaurant_reviews:login')
    restaurant = get_object_or_404(Restaurant, id=restaurant_id)
    CUISINE_CHOICES = [
        'Italian', 'Japanese', 'American', 'Mexican', 'Chinese', 'Indian', 'French', 'Mediterranean', 'Other'
    ]
    if request.method == 'POST':
        restaurant.name = request.POST.get('name', '').strip()
        restaurant.address = request.POST.get('address', '').strip()
        restaurant.city = request.POST.get('city', '').strip()
        restaurant.cuisine_type = request.POST.get('cuisine_type', '').strip()
        restaurant.description = request.POST.get('description', '').strip()
        image = request.FILES.get('image')
        if image:
            restaurant.image = image
        errors = Restaurant.objects.restaurant_validator(request.POST)
        if errors:
            for err in errors.values():
                messages.error(request, err)
            return render(request, 'edit_restaurant.html', {'restaurant': restaurant, 'cuisine_choices': CUISINE_CHOICES})
        restaurant.save()
        messages.success(request, 'Restaurant updated successfully!')
        return redirect('restaurant_reviews:admin_dashboard')
    return render(request, 'edit_restaurant.html', {'restaurant': restaurant, 'cuisine_choices': CUISINE_CHOICES})

def delete_restaurant(request, restaurant_id):
    user = get_logged_in_user(request)
    if not user or user.role != 'admin':
        return redirect('restaurant_reviews:login')
    restaurant = get_object_or_404(Restaurant, id=restaurant_id)
    restaurant.delete()
    messages.success(request, 'Restaurant deleted successfully!')
    return redirect('restaurant_reviews:admin_dashboard')

def delete_review(request, review_id):
    user = get_logged_in_user(request)
    if not user or user.role != 'admin':
        return redirect('restaurant_reviews:login')
    review = get_object_or_404(Review, id=review_id)
    review.delete()
    messages.success(request, 'Review deleted!')
    return redirect('restaurant_reviews:admin_dashboard')

def restaurant_detail(request, restaurant_id):
    restaurant = get_object_or_404(Restaurant, id=restaurant_id)
    reviews = Review.objects.filter(restaurant=restaurant).select_related('user').order_by('-created_at')
    user = get_logged_in_user(request)
    user_review = None
    if user:
        user_review = reviews.filter(user=user).first()
    average_rating = reviews.aggregate(avg=Avg('rating'))['avg'] or 0
    rating_counts = {i: reviews.filter(rating=i).count() for i in range(1, 6)}
    total_reviews = reviews.count()
    
    context = {
        'restaurant': restaurant,
        'reviews': reviews,
        'user_review': user_review,
        'average_rating': average_rating,
        'rating_counts': rating_counts,
        'total_reviews': total_reviews,
    }
    return render(request, 'restaurant_detail.html', context)

def edit_review(request, review_id):
    user = get_logged_in_user(request)
    review = get_object_or_404(Review, id=review_id, user=user)
    print("review", review.rating, type(review.rating))
    print("user", user)
    if request.method == 'POST':
        rating = int(request.POST.get('rating', 0))
        comment = request.POST.get('comment', '').strip()
        errors = Review.objects.review_validator(request.POST)
        if errors:
            for err in errors.values():
                messages.error(request, err)
        else:
            review.rating = rating
            review.comment = comment
            review.save()
            messages.success(request, 'Review updated!')
            return redirect('restaurant_reviews:restaurant_detail', restaurant_id=review.restaurant.id)
    return render(request, 'edit_review.html', {'review': review})

def delete_review_user(request, review_id):
    user = get_logged_in_user(request)
    review = get_object_or_404(Review, id=review_id, user=user)
    restaurant_id = review.restaurant.id
    review.delete()
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'success': True})
    messages.success(request, 'Review deleted!')
    return redirect('restaurant_reviews:restaurant_detail', restaurant_id=restaurant_id)

def about(request):
    return render(request, 'about.html')

def create_review(request, restaurant_id):
    user = get_logged_in_user(request)
    if not user:
        return JsonResponse({'success': False, 'errors': ['Authentication required.']}, status=403)
    restaurant = get_object_or_404(Restaurant, id=restaurant_id)
    user_review = Review.objects.filter(restaurant=restaurant, user=user).first()
    if user_review:
        return JsonResponse({'success': False, 'errors': ['You have already reviewed this restaurant.']}, status=400)
    if request.method == 'POST':
        rating = int(request.POST.get('rating', 0))
        comment = request.POST.get('comment', '').strip()
        errors = Review.objects.review_validator(request.POST)
        if errors:
            return JsonResponse({'success': False, 'errors': list(errors.values())}, status=400)
        review = Review.objects.create(user=user, restaurant=restaurant, rating=rating, comment=comment, created_at=timezone.now())
        return JsonResponse({
            'success': True,
            'review': {
                'id': review.id,
                'user': f'{user.first_name} {user.last_name}',
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
        })
    return JsonResponse({'success': False, 'errors': ['Invalid request.']}, status=400)

def delete_review_api(request, review_id):
    user = get_logged_in_user(request)
    if not user:
        return JsonResponse({'success': False, 'errors': ['Authentication required.']}, status=403)
    review = get_object_or_404(Review, id=review_id, user=user)
    if request.method == 'POST':
        review.delete()
        return JsonResponse({'success': True})
    return JsonResponse({'success': False, 'errors': ['Invalid request.']}, status=400)

