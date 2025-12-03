"""
Multi-Tenant Auth 装饰器 - 极简权限检查
"""

from functools import wraps
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from .services import PermissionService
from .exceptions import PermissionDenied


def require_permission(user_id=None, workspace_id=None, action=None):
    """
    权限检查装饰器 - 极简API

    Args:
        user_id: 用户ID的获取方式
            - 直接传值: "user-uuid"
            - 从request获取: "request.auth_user_id"
            - 从参数获取: "user_id" (函数参数)
        workspace_id: 工作空间ID的获取方式
            - 直接传值: "workspace-uuid"
            - 从对象获取: "project.id" (参数project的id属性)
            - 从参数获取: "workspace_id" (函数参数)
        action: 操作类型
            - 字符串: "view", "edit", "delete", "share", "admin"

    使用示例:
        @require_permission(
            user_id="request.auth_user_id",    # 从JWT中间件获取
            workspace_id="project.id",         # 从参数project对象获取
            action="edit"                      # 检查编辑权限
        )
        def edit_project(request, project_id):
            project = Project.objects.get(id=project_id)
            # 有权限才执行这里

        @require_permission(
            user_id=user_id,                   # 直接使用函数参数
            workspace_id=workspace_id,         # 直接使用函数参数
            action="delete"
        )
        def delete_workspace(request, user_id, workspace_id):
            # 有权限才执行这里
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                # 获取用户ID
                user_uuid = _resolve_value(user_id, request, *args, **kwargs)
                if not user_uuid:
                    return JsonResponse({
                        'error': 'User ID required',
                        'code': 'USER_ID_MISSING'
                    }, status=401)

                # 获取工作空间ID
                workspace_uuid = _resolve_value(workspace_id, request, *args, **kwargs)
                if not workspace_uuid:
                    return JsonResponse({
                        'error': 'Workspace ID required',
                        'code': 'WORKSPACE_ID_MISSING'
                    }, status=400)

                # 检查权限
                permission_service = PermissionService()
                if not permission_service.check_permission(user_uuid, workspace_uuid, action):
                    return JsonResponse({
                        'error': f'Permission denied for action: {action}',
                        'code': 'PERMISSION_DENIED'
                    }, status=403)

                # 权限检查通过，执行视图函数
                return view_func(request, *args, **kwargs)

            except PermissionDenied:
                return JsonResponse({
                    'error': f'Permission denied for action: {action}',
                    'code': 'PERMISSION_DENIED'
                }, status=403)
            except Exception as e:
                return JsonResponse({
                    'error': 'Internal server error',
                    'code': 'INTERNAL_ERROR',
                    'message': str(e)
                }, status=500)

        return wrapper
    return decorator


def _resolve_value(value, request, *args, **kwargs):
    """
    解析参数值，支持多种来源

    Args:
        value: 要解析的值，可以是字符串或直接值
        request: Django request对象
        *args: 函数位置参数
        **kwargs: 函数关键字参数

    Returns:
        解析后的实际值
    """
    # 如果直接传值（不是字符串），直接返回
    if not isinstance(value, str):
        return value

    # 解析字符串表达式
    if value.startswith('request.'):
        # 从request对象获取，如 "request.auth_user_id"
        attr_path = value[9:]  # 去掉 "request."
        return _get_nested_attr(request, attr_path)

    elif '.' in value:
        # 从参数对象获取，如 "project.id"
        obj_name, attr_path = value.split('.', 1)
        if obj_name in kwargs:
            return _get_nested_attr(kwargs[obj_name], attr_path)
        else:
            raise ValueError(f"Parameter '{obj_name}' not found in view function")

    elif value in kwargs:
        # 从函数参数直接获取
        return kwargs[value]

    else:
        # 静态值，直接返回
        return value


def _get_nested_attr(obj, attr_path):
    """
    获取嵌套属性值

    Args:
        obj: 对象
        attr_path: 属性路径，如 "user.id" 或 "project.workspace.id"

    Returns:
        属性值
    """
    attrs = attr_path.split('.')
    current = obj

    try:
        for attr in attrs:
            if hasattr(current, attr):
                current = getattr(current, attr)
            elif isinstance(current, dict) and attr in current:
                current = current[attr]
            else:
                return None
        return current
    except (AttributeError, KeyError, TypeError):
        return None


# 便捷装饰器别名
def require_edit_permission(user_id=None, workspace_id=None):
    """编辑权限检查"""
    return require_permission(user_id=user_id, workspace_id=workspace_id, action='edit')


def require_delete_permission(user_id=None, workspace_id=None):
    """删除权限检查"""
    return require_permission(user_id=user_id, workspace_id=workspace_id, action='delete')


def require_admin_permission(user_id=None, workspace_id=None):
    """管理权限检查"""
    return require_permission(user_id=user_id, workspace_id=workspace_id, action='admin')


def require_view_permission(user_id=None, workspace_id=None):
    """查看权限检查"""
    return require_permission(user_id=user_id, workspace_id=workspace_id, action='view')


def require_share_permission(user_id=None, workspace_id=None):
    """分享权限检查"""
    return require_permission(user_id=user_id, workspace_id=workspace_id, action='share')