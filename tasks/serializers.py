from rest_framework import serializers

from tasks.models import Task, Tag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    tags = TagSerializer(many=True, read_only=True)
    files = serializers.FileField(required=False, allow_null=True)

    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'executor', 'created_at', 'status', 'tags', 'files']

class TaskCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['title', 'description', 'executor', 'status', 'tags', 'files']
