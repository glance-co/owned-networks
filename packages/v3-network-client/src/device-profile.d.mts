// SPDX-License-Identifier: Apache-2.0
import type {NetworkIdentity,PreparedNetworkWrite} from './index.mjs';
export interface PendingNetworkWrite {host:string;operation:PreparedNetworkWrite;action:string}
export interface DeviceNetworkProfile {identity:NetworkIdentity;displayName:string;recoveryReviewed:boolean;readThrough:Record<string,number>;drafts:Record<string,Record<string,string>>;pendingWrite?:PendingNetworkWrite|null}
export function readDeviceProfile(accountId?:string|null):Promise<DeviceNetworkProfile|null>;
export function saveDeviceProfile(accountId:string|null,profile:DeviceNetworkProfile):Promise<DeviceNetworkProfile>;
export function updateDeviceProfile(accountId:string|null,expectedActor:string,changes:Partial<Omit<DeviceNetworkProfile,'identity'>>):Promise<DeviceNetworkProfile>;
