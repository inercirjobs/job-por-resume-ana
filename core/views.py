import boto3
import time
import os
import razorpay
import random
import hmac
import hashlib
import tempfile
import uuid
import requests
from urllib.parse import urlparse

from django.conf import settings
from django.shortcuts import get_object_or_404, redirect
from django.http import StreamingHttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import (
    api_view, permission_classes, action
)
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.views import APIView

from botocore.exceptions import ClientError
from botocore.client import Config

from .models import User, Job, JobApplication
from .utils import get_redirect_url
from .resume_analysis import (
    extract_metadata_text,
    looks_like_resume,
    sbert_similarity_percent,
    extract_text_from_pdf_bytes
)

from google.oauth2 import id_token
from google.auth.transport import requests as googleRequest

client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

# -------------------------------
# ✅ AWS Utility
# -------------------------------
def generate_presigned_url(key: str, expiration=3600):
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
        config=Config(signature_version='s3v4')
    )
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': key},
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        print(f"Presigned URL generation error: {e}")
        return None

def extract_key_from_url(url: str) -> str:
    """Extracts the S3 object key from a full URL."""
    return urlparse(url).path.lstrip('/')


# -------------------------------
# ✅ Permissions
# -------------------------------
class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user

class IsHROrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ['hr', 'admin']

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

class AllowAnyPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return True


# -------------------------------
# ✅ Resume Analysis API
# -------------------------------
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def analyze_resumes_view(request, job_id: str) -> Response:
    user = request.user

    if user.role != 'hr':
        return Response({"error": "Only HRs can access this."}, status=403)

    job = get_object_or_404(Job, id=job_id, created_by=user)
    applications = JobApplication.objects.filter(job=job)
    job_description = job.description or ""

    analysis_results = []

    for app in applications:
        if not app.resume_url:
            continue

        # ✅ Extract resume key from full URL
        resume_key = extract_key_from_url(app.resume_url)

        # ✅ Generate fresh pre-signed URL
        presigned_url = generate_presigned_url(resume_key)
        if not presigned_url:
            continue

        try:
            # ✅ Download PDF from S3
            response = requests.get(presigned_url)
            resume_bytes = response.content

            # ✅ Extract text
            resume_text = extract_text_from_pdf_bytes(resume_bytes)

            # ✅ Resume quality check
            is_resume, resume_note, has_neg = looks_like_resume(resume_text)

            if not is_resume:
                analysis_results.append({
                    'application_id': app.application_id,
                    'name': app.name,
                    'valid_resume': False,
                    'reason': resume_note,
                    'score': 0,
                    'resume_url': presigned_url,
                })
                continue

            # ✅ Similarity check
            similarity = sbert_similarity_percent(job_description, resume_text)
            if has_neg:
                similarity = max(0, similarity - 10)

            analysis_results.append({
                'application_id': app.application_id,
                'name': app.name,
                'valid_resume': True,
                'score': similarity,
                'resume_url': presigned_url,
            })

        except Exception as e:
            print(f"Error analyzing resume for {app.name}: {e}")
            continue

    return Response(analysis_results, status=200)


# -------------------------------
# ✅ Utility for redirect after login
# -------------------------------
def get_redirect_url(role):
    if role == 'user':
        return '/job-seeker-dashboard'
    elif role == 'hr':
        return '/company-dashboard'
    elif role == 'admin':
        return '/admin-dashboard'
    return '/'
