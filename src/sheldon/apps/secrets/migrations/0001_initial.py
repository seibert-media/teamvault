# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Password'
        db.create_table(u'secrets_password', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('last_modified', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=92)),
            ('id_token', self.gf('django.db.models.fields.CharField')(default='GZAtMLQLmnskE04Gvh7lv2zOP3Nlb2B3', unique=True, max_length=32)),
            ('encrypted_password', self.gf('django.db.models.fields.TextField')()),
        ))
        db.send_create_signal(u'secrets', ['Password'])


    def backwards(self, orm):
        # Deleting model 'Password'
        db.delete_table(u'secrets_password')


    models = {
        u'secrets.password': {
            'Meta': {'object_name': 'Password'},
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'encrypted_password': ('django.db.models.fields.TextField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'id_token': ('django.db.models.fields.CharField', [], {'default': "'AmbIIqvLzmZm0yY6P9yR0nkTzQS0Y8bx'", 'unique': 'True', 'max_length': '32'}),
            'last_modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '92'})
        }
    }

    complete_apps = ['secrets']