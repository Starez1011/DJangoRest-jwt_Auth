from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

#Custom User Manager
class UserManager(BaseUserManager):
    def create_user(self, email, name,tc, password=None,password1=None):
        """
        Creates and saves a superuser with the given email,name,tc
        and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            tc=tc,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name,tc, password=None):
        """
        Creates and saves a superuser with the given email,name,tc
        and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
            tc=tc,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

#Custom User model
class User (AbstractBaseUser):
    email = models.EmailField(verbose_name='email', max_length=255, unique=True)
    name = models.CharField(max_length=30)
    tc = models.BooleanField()
    created_at = models.DateTimeField(verbose_name='created at', auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name='updated_at', auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','tc']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    #for specific permissions
    def has_perm(self, perm, obj=None):
        return self.is_admin
    #Does this user have permissions to view this app?
    def has_module_perms(self, app_label):
        return True
    @property
    def is_staff(self):
        return self.is_admin