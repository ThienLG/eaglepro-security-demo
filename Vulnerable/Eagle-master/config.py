# config.py
import os

class Config:
    SECRET_KEY = 'eaglepro_demo_key_2024'
    DATABASE = 'eaglepro.db'
    
    # Avatar configurations
    AVATARS = {
        'admin': 'admin_avatar.png',
        'HusThi_IA': 'husthi_avatar.png', 
        'Collie_Minh': 'collie_avatar.png',
        'LazyBeo': 'lazybeo_avatar.png',
        'default': 'husthi_avatar.png'
    }