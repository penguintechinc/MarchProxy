"""
Mapping configuration models for MarchProxy Manager

Copyright (C) 2025 MarchProxy Contributors
Licensed under GNU Affero General Public License v3.0
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from pydal import DAL, Field
from pydantic import BaseModel, validator


class MappingModel:
    """Mapping model for source-destination service routing"""

    @staticmethod
    def define_table(db: DAL):
        """Define mapping table in database"""
        return db.define_table(
            'mappings',
            Field('name', type='string', unique=True, required=True, length=100),
            Field('description', type='text'),
            Field('source_services', type='json', required=True),
            Field('dest_services', type='json', required=True),
            Field('cluster_id', type='reference clusters', required=True),
            Field('protocols', type='json', default=['tcp']),
            Field('ports', type='json', required=True),
            Field('auth_required', type='boolean', default=True),
            Field('priority', type='integer', default=100),
            Field('is_active', type='boolean', default=True),
            Field('created_by', type='reference users', required=True),
            Field('created_at', type='datetime', default=datetime.utcnow),
            Field('updated_at', type='datetime', update=datetime.utcnow),
            Field('comments', type='text'),
            Field('metadata', type='json'),
        )

    @staticmethod
    def create_mapping(db: DAL, name: str, source_services: List[Union[int, str]],
                      dest_services: List[Union[int, str]], ports: List[Union[int, str]],
                      cluster_id: int, created_by: int, protocols: List[str] = None,
                      auth_required: bool = True, priority: int = 100,
                      description: str = None, comments: str = None) -> int:
        """Create new mapping configuration"""

        # Validate and normalize source services
        normalized_sources = MappingModel._normalize_service_list(db, source_services, cluster_id)
        if not normalized_sources:
            raise ValueError("No valid source services provided")

        # Validate and normalize destination services
        normalized_dests = MappingModel._normalize_service_list(db, dest_services, cluster_id)
        if not normalized_dests:
            raise ValueError("No valid destination services provided")

        # Validate and normalize ports
        normalized_ports = MappingModel._normalize_port_list(ports)
        if not normalized_ports:
            raise ValueError("No valid ports provided")

        # Default protocols
        if not protocols:
            protocols = ['tcp']

        mapping_id = db.mappings.insert(
            name=name,
            description=description,
            source_services=normalized_sources,
            dest_services=normalized_dests,
            cluster_id=cluster_id,
            protocols=protocols,
            ports=normalized_ports,
            auth_required=auth_required,
            priority=priority,
            created_by=created_by,
            comments=comments
        )

        return mapping_id

    @staticmethod
    def _normalize_service_list(db: DAL, services: List[Union[int, str]], cluster_id: int) -> List[Dict[str, Any]]:
        """Normalize service list to include IDs and metadata"""
        normalized = []

        for service in services:
            if service == "all":
                # Special case: all services in cluster
                cluster_services = db(
                    (db.services.cluster_id == cluster_id) &
                    (db.services.is_active == True)
                ).select()

                normalized.append({
                    'type': 'all',
                    'cluster_id': cluster_id,
                    'count': len(cluster_services)
                })
                break  # 'all' supersedes individual services

            elif isinstance(service, str) and service.startswith("collection:"):
                # Collection reference
                collection_name = service[11:]  # Remove 'collection:' prefix
                collection_services = db(
                    (db.services.cluster_id == cluster_id) &
                    (db.services.collection == collection_name) &
                    (db.services.is_active == True)
                ).select()

                if collection_services:
                    normalized.append({
                        'type': 'collection',
                        'name': collection_name,
                        'cluster_id': cluster_id,
                        'service_ids': [s.id for s in collection_services],
                        'count': len(collection_services)
                    })

            elif isinstance(service, (int, str)) and str(service).isdigit():
                # Individual service ID
                service_id = int(service)
                service_record = db(
                    (db.services.id == service_id) &
                    (db.services.cluster_id == cluster_id) &
                    (db.services.is_active == True)
                ).select().first()

                if service_record:
                    normalized.append({
                        'type': 'service',
                        'id': service_id,
                        'name': service_record.name,
                        'ip_fqdn': service_record.ip_fqdn,
                        'port': service_record.port,
                        'cluster_id': cluster_id
                    })

        return normalized

    @staticmethod
    def _normalize_port_list(ports: List[Union[int, str]]) -> List[Dict[str, Any]]:
        """Normalize port list to handle ranges and individual ports"""
        normalized = []

        for port in ports:
            if isinstance(port, int):
                # Single port
                if 1 <= port <= 65535:
                    normalized.append({
                        'type': 'single',
                        'port': port
                    })

            elif isinstance(port, str):
                # Port range (e.g., "8000-8100") or comma-separated (e.g., "80,443,8080")
                if '-' in port and ',' not in port:
                    # Range
                    try:
                        start, end = map(int, port.split('-'))
                        if 1 <= start <= end <= 65535:
                            normalized.append({
                                'type': 'range',
                                'start': start,
                                'end': end
                            })
                    except ValueError:
                        pass

                elif ',' in port:
                    # Comma-separated list
                    try:
                        port_list = [int(p.strip()) for p in port.split(',')]
                        valid_ports = [p for p in port_list if 1 <= p <= 65535]
                        if valid_ports:
                            normalized.append({
                                'type': 'list',
                                'ports': valid_ports
                            })
                    except ValueError:
                        pass

                else:
                    # Single port as string
                    try:
                        port_num = int(port)
                        if 1 <= port_num <= 65535:
                            normalized.append({
                                'type': 'single',
                                'port': port_num
                            })
                    except ValueError:
                        pass

        return normalized

    @staticmethod
    def get_cluster_mappings(db: DAL, cluster_id: int, user_id: int = None) -> List[Dict[str, Any]]:
        """Get mappings for cluster (with user access control)"""
        query = (db.mappings.cluster_id == cluster_id) & (db.mappings.is_active == True)

        # If user_id provided and user is not admin, filter by accessible services
        if user_id:
            user = db.users[user_id]
            if not user or not user.is_admin:
                # Get user's accessible services
                user_services = db(
                    (db.user_service_assignments.user_id == user_id) &
                    (db.user_service_assignments.is_active == True)
                ).select(db.user_service_assignments.service_id)

                accessible_service_ids = [assignment.service_id for assignment in user_services]

                # Filter mappings that involve user's services
                # This is complex because services are stored as JSON arrays
                # For now, we'll fetch all and filter in Python
                all_mappings = db(query).select()
                filtered_mappings = []

                for mapping in all_mappings:
                    has_access = False

                    # Check if any source or destination service is accessible
                    for source in mapping.source_services:
                        if source.get('type') == 'service' and source.get('id') in accessible_service_ids:
                            has_access = True
                            break

                    if not has_access:
                        for dest in mapping.dest_services:
                            if dest.get('type') == 'service' and dest.get('id') in accessible_service_ids:
                                has_access = True
                                break

                    if has_access:
                        filtered_mappings.append(mapping)

                return [
                    {
                        'id': mapping.id,
                        'name': mapping.name,
                        'description': mapping.description,
                        'source_services': mapping.source_services,
                        'dest_services': mapping.dest_services,
                        'protocols': mapping.protocols,
                        'ports': mapping.ports,
                        'auth_required': mapping.auth_required,
                        'priority': mapping.priority,
                        'created_at': mapping.created_at
                    }
                    for mapping in filtered_mappings
                ]

        # Admin or no user filter
        mappings = db(query).select(orderby=db.mappings.priority)
        return [
            {
                'id': mapping.id,
                'name': mapping.name,
                'description': mapping.description,
                'source_services': mapping.source_services,
                'dest_services': mapping.dest_services,
                'protocols': mapping.protocols,
                'ports': mapping.ports,
                'auth_required': mapping.auth_required,
                'priority': mapping.priority,
                'created_at': mapping.created_at
            }
            for mapping in mappings
        ]

    @staticmethod
    def resolve_mapping_services(db: DAL, mapping_id: int) -> Optional[Dict[str, Any]]:
        """Resolve mapping to concrete service configurations for proxy"""
        mapping = db(
            (db.mappings.id == mapping_id) &
            (db.mappings.is_active == True)
        ).select().first()

        if not mapping:
            return None

        # Resolve source services
        resolved_sources = []
        for source in mapping.source_services:
            resolved_sources.extend(MappingModel._resolve_service_reference(db, source, mapping.cluster_id))

        # Resolve destination services
        resolved_destinations = []
        for dest in mapping.dest_services:
            resolved_destinations.extend(MappingModel._resolve_service_reference(db, dest, mapping.cluster_id))

        return {
            'id': mapping.id,
            'name': mapping.name,
            'sources': resolved_sources,
            'destinations': resolved_destinations,
            'protocols': mapping.protocols,
            'ports': mapping.ports,
            'auth_required': mapping.auth_required,
            'priority': mapping.priority
        }

    @staticmethod
    def _resolve_service_reference(db: DAL, service_ref: Dict[str, Any], cluster_id: int) -> List[Dict[str, Any]]:
        """Resolve a service reference to concrete service configurations"""
        if service_ref['type'] == 'all':
            # All services in cluster
            services = db(
                (db.services.cluster_id == cluster_id) &
                (db.services.is_active == True)
            ).select()

        elif service_ref['type'] == 'collection':
            # Services in collection
            services = db(
                (db.services.cluster_id == cluster_id) &
                (db.services.collection == service_ref['name']) &
                (db.services.is_active == True)
            ).select()

        elif service_ref['type'] == 'service':
            # Single service
            services = db(
                (db.services.id == service_ref['id']) &
                (db.services.is_active == True)
            ).select()

        else:
            return []

        return [
            {
                'id': service.id,
                'name': service.name,
                'ip_fqdn': service.ip_fqdn,
                'port': service.port,
                'protocol': service.protocol,
                'auth_type': service.auth_type,
                'tls_enabled': service.tls_enabled
            }
            for service in services
        ]

    @staticmethod
    def find_matching_mappings(db: DAL, source_service_id: int, dest_service_id: int,
                              protocol: str, port: int) -> List[Dict[str, Any]]:
        """Find mappings that match source, destination, protocol, and port"""
        # Get cluster for source service
        source_service = db.services[source_service_id]
        if not source_service:
            return []

        cluster_id = source_service.cluster_id

        # Get all active mappings for cluster
        mappings = db(
            (db.mappings.cluster_id == cluster_id) &
            (db.mappings.is_active == True)
        ).select(orderby=db.mappings.priority)

        matching = []
        for mapping in mappings:
            if (MappingModel._service_matches(source_service_id, mapping.source_services, cluster_id) and
                MappingModel._service_matches(dest_service_id, mapping.dest_services, cluster_id) and
                protocol in mapping.protocols and
                MappingModel._port_matches(port, mapping.ports)):

                matching.append({
                    'id': mapping.id,
                    'name': mapping.name,
                    'auth_required': mapping.auth_required,
                    'priority': mapping.priority
                })

        return matching

    @staticmethod
    def _service_matches(service_id: int, service_refs: List[Dict[str, Any]], cluster_id: int) -> bool:
        """Check if service ID matches any service reference"""
        for ref in service_refs:
            if ref['type'] == 'all':
                return True
            elif ref['type'] == 'service' and ref['id'] == service_id:
                return True
            elif ref['type'] == 'collection':
                # Check if service belongs to collection
                service = db.services[service_id]
                return service and service.collection == ref['name']
        return False

    @staticmethod
    def _port_matches(port: int, port_refs: List[Dict[str, Any]]) -> bool:
        """Check if port matches any port reference"""
        for ref in port_refs:
            if ref['type'] == 'single' and ref['port'] == port:
                return True
            elif ref['type'] == 'range' and ref['start'] <= port <= ref['end']:
                return True
            elif ref['type'] == 'list' and port in ref['ports']:
                return True
        return False


# Pydantic models for request/response validation
class CreateMappingRequest(BaseModel):
    name: str
    description: Optional[str] = None
    source_services: List[Union[int, str]]
    dest_services: List[Union[int, str]]
    cluster_id: int
    protocols: List[str] = ['tcp']
    ports: List[Union[int, str]]
    auth_required: bool = True
    priority: int = 100
    comments: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3:
            raise ValueError('Mapping name must be at least 3 characters long')
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Mapping name can only contain alphanumeric characters, hyphens, and underscores')
        return v.lower()

    @validator('protocols')
    def validate_protocols(cls, v):
        valid_protocols = ['tcp', 'udp', 'icmp', 'http', 'https']
        for protocol in v:
            if protocol not in valid_protocols:
                raise ValueError(f'Invalid protocol: {protocol}. Must be one of: {valid_protocols}')
        return [p.lower() for p in v]

    @validator('ports')
    def validate_ports(cls, v):
        if not v:
            raise ValueError('At least one port must be specified')

        for port in v:
            if isinstance(port, int):
                if not (1 <= port <= 65535):
                    raise ValueError(f'Port {port} must be between 1 and 65535')
            elif isinstance(port, str):
                # Validate port range or list format
                if '-' in port and ',' not in port:
                    # Range format
                    try:
                        start, end = map(int, port.split('-'))
                        if not (1 <= start <= end <= 65535):
                            raise ValueError(f'Port range {port} invalid')
                    except ValueError:
                        raise ValueError(f'Invalid port range format: {port}')
                elif ',' in port:
                    # List format
                    try:
                        port_list = [int(p.strip()) for p in port.split(',')]
                        for p in port_list:
                            if not (1 <= p <= 65535):
                                raise ValueError(f'Port {p} must be between 1 and 65535')
                    except ValueError:
                        raise ValueError(f'Invalid port list format: {port}')
                else:
                    # Single port as string
                    try:
                        port_num = int(port)
                        if not (1 <= port_num <= 65535):
                            raise ValueError(f'Port {port_num} must be between 1 and 65535')
                    except ValueError:
                        raise ValueError(f'Invalid port format: {port}')

        return v

    @validator('priority')
    def validate_priority(cls, v):
        if not (1 <= v <= 1000):
            raise ValueError('Priority must be between 1 and 1000')
        return v


class UpdateMappingRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    source_services: Optional[List[Union[int, str]]] = None
    dest_services: Optional[List[Union[int, str]]] = None
    protocols: Optional[List[str]] = None
    ports: Optional[List[Union[int, str]]] = None
    auth_required: Optional[bool] = None
    priority: Optional[int] = None
    comments: Optional[str] = None


class MappingResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    source_services: List[Dict[str, Any]]
    dest_services: List[Dict[str, Any]]
    cluster_id: int
    protocols: List[str]
    ports: List[Dict[str, Any]]
    auth_required: bool
    priority: int
    created_at: datetime


class ResolvedMappingResponse(BaseModel):
    id: int
    name: str
    sources: List[Dict[str, Any]]
    destinations: List[Dict[str, Any]]
    protocols: List[str]
    ports: List[Dict[str, Any]]
    auth_required: bool
    priority: int