"""FastAPI application that exposes virtualization management endpoints."""
from __future__ import annotations

import os
from typing import Dict, List

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from .config import HostConfig, HostRegistry, load_host_registry, resolve_config_path
from .qemu import QEMUError, QEMUManager
from .security import TokenAuth, load_tokens_from_env
from .ssh import CommandResult, SSHClientFactory, SSHCommandRunner, SSHError


def command_result_to_dict(result: CommandResult) -> Dict[str, object]:
    return {
        "command": list(result.command),
        "exit_status": result.exit_status,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def parse_dominfo(stdout: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def create_app() -> FastAPI:
    config_path = resolve_config_path(os.getenv("MANAGEMENT_CONFIG_PATH"))
    registry = load_host_registry(config_path)

    tokens = load_tokens_from_env()
    try:
        auth = TokenAuth(tokens)
    except ValueError as exc:  # pragma: no cover - startup validation
        raise RuntimeError(
            "MANAGEMENT_API_TOKENS environment variable must contain at least one token"
        ) from exc

    app = FastAPI(
        title="QEMU Management Service",
        description="Secure API for managing QEMU virtual machines over SSH",
        version="1.0.0",
    )

    protected_router = APIRouter(dependencies=[Depends(auth)])

    def get_registry() -> HostRegistry:
        return registry

    def get_host_config(host_name: str, registry: HostRegistry = Depends(get_registry)) -> HostConfig:
        try:
            return registry.get(host_name)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    def get_qemu_manager(host_config: HostConfig = Depends(get_host_config)) -> QEMUManager:
        factory = SSHClientFactory(host_config)
        runner = SSHCommandRunner(factory)
        return QEMUManager(runner)

    @app.get("/health")
    async def healthcheck() -> Dict[str, str]:
        return {"status": "ok"}

    @protected_router.get("/hosts")
    async def list_hosts(registry: HostRegistry = Depends(get_registry)) -> List[Dict[str, object]]:
        hosts: List[Dict[str, object]] = []
        for host in registry.list():
            hosts.append(
                {
                    "name": host.name,
                    "hostname": host.hostname,
                    "port": host.port,
                    "username": host.username,
                    "allow_unknown_hosts": host.allow_unknown_hosts,
                }
            )
        return hosts

    @protected_router.get("/hosts/{host_name}/vms")
    async def list_host_vms(manager: QEMUManager = Depends(get_qemu_manager)) -> List[Dict[str, object]]:
        vms: List[Dict[str, object]] = []
        for vm in manager.list_vms():
            vms.append({"name": vm.name, "state": vm.state, "id": vm.id})
        return vms

    @protected_router.get("/hosts/{host_name}/vms/{vm_name}")
    async def get_vm_info(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.get_vm_info(vm_name)
        return {"dominfo": parse_dominfo(result.stdout), "raw": command_result_to_dict(result)}

    @protected_router.post("/hosts/{host_name}/vms/{vm_name}/start")
    async def start_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.start_vm(vm_name)
        return command_result_to_dict(result)

    @protected_router.post("/hosts/{host_name}/vms/{vm_name}/shutdown")
    async def shutdown_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.shutdown_vm(vm_name)
        return command_result_to_dict(result)

    @protected_router.post("/hosts/{host_name}/vms/{vm_name}/force-stop")
    async def force_stop_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.force_stop_vm(vm_name)
        return command_result_to_dict(result)

    @protected_router.post("/hosts/{host_name}/vms/{vm_name}/reboot")
    async def reboot_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.reboot_vm(vm_name)
        return command_result_to_dict(result)

    app.include_router(protected_router)

    @app.exception_handler(QEMUError)
    async def handle_qemu_error(_: object, exc: QEMUError):
        payload: Dict[str, object] = {"detail": str(exc)}
        if exc.result is not None:
            payload["command"] = command_result_to_dict(exc.result)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=payload)

    @app.exception_handler(SSHError)
    async def handle_ssh_error(_: object, exc: SSHError):
        return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content={"detail": str(exc)})

    return app


app = create_app()


__all__ = ["app", "create_app"]
