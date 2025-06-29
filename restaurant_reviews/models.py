from django.db import models
import re
import bcrypt


class UserManager(models.Manager):
    def registration_validator(self, postData):
        errors = {}
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        if len(postData.get('first_name', '')) < 2:
            errors['first_name'] = "First name must be at least 2 characters"
        if len(postData.get('last_name', '')) < 2:
            errors['last_name'] = "Last name must be at least 2 characters"
        if not EMAIL_REGEX.match(postData.get('email', '')):
            errors['email'] = "Invalid email address"
        if User.objects.filter(email=postData.get('email', '')).exists():
            errors['email'] = "Email already exists"
        if len(postData.get('password', '')) < 8:
            errors['password'] = "Password must be at least 8 characters"
        if postData.get('password') != postData.get('confirm_password'):
            errors['confirm_password'] = "Passwords do not match"
        return errors

    def login_validator(self, postData):
        errors = {}
        user = User.objects.filter(email=postData.get('email'))
        if not user:
            errors['login'] = "Invalid email/password"
        elif not bcrypt.checkpw(postData.get('password', '').encode(), user[0].password.encode()):
            errors['login'] = "Invalid email/password"
        return errors

class RestaurantManager(models.Manager):
    def restaurant_validator(self, postData):
        errors = {}
        if len(postData.get('name', '')) < 2:
            errors['name'] = "Restaurant name must be at least 2 characters"
        if len(postData.get('description', '')) < 10:
            errors['description'] = "Description must be at least 10 characters"
        if len(postData.get('address', '')) < 5:
            errors['address'] = "Address must be at least 5 characters"
        if len(postData.get('city', '')) < 2:
            errors['city'] = "City name must be at least 2 characters"
        if len(postData.get('cuisine_type', '')) < 2:
            errors['cuisine_type'] = "Cuisine type must be at least 2 characters"
        return errors

class ReviewManager(models.Manager):
    def review_validator(self, postData):
        errors = {}
        try:
            rating = int(postData.get('rating', 0))
            if rating < 1 or rating > 5:
                errors['rating'] = "Rating must be between 1 and 5"
        except ValueError:
            errors['rating'] = "Rating must be a number between 1 and 5"
        if len(postData.get('comment', '')) < 5:
            errors['comment'] = "Comment must be at least 5 characters"
        return errors

class User(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    name = models.CharField(max_length=200, default=f"{first_name} {last_name}")
    email = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='user')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

class Restaurant(models.Model):
    name = models.CharField(max_length=500)
    description = models.TextField(max_length=100)
    address = models.CharField(max_length=255)
    city = models.CharField(max_length=50)
    cuisine_type = models.CharField(max_length=50)
    image = models.ImageField(upload_to='restaurant_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = RestaurantManager()

    def __str__(self):
        return self.name

class Review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reviews')
    restaurant = models.ForeignKey(Restaurant, on_delete=models.CASCADE, related_name='reviews')
    rating = models.IntegerField()
    comment = models.TextField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = ReviewManager()

    def __str__(self):
        return f"{self.user.name} - {self.restaurant.name} ({self.rating})"
