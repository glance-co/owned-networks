import type { IncomingMessage, ServerResponse, Server } from 'node:http';
export type NetworkState = { id:string; host:string; sequence:number; head:string; frozen:boolean; destination?:string; createdAt:string; events:string[]; [key:string]:unknown };
export interface NetworkStore {
  kind:string;
  durableHandoff:boolean;
  health():Promise<{store:string;durableHandoff:boolean}>;
  get(id:string):Promise<NetworkState|null>;
  list(options?:{afterId?:string;limit?:number}):Promise<{items:NetworkState[];hasMore:boolean}>;
  transaction<T>(id:string,work:(state:NetworkState|null)=>Promise<{state?:NetworkState;result:T}>):Promise<T>;
  takeRate(key:string,limit:number,windowMs?:number):Promise<boolean>;
  close():Promise<void>;
}
export type NetworkHandler=((request:IncomingMessage,response:ServerResponse)=>Promise<void>)&{close():Promise<void>};
export type HandlerOptions={store:NetworkStore;origin:string;webOrigins?:string[];now?:()=>number;clientAddress?:(request:IncomingMessage)=>string;verifySourceFreeze?:(archived:NetworkState,destination:string)=>Promise<void>};
export function createNetworkHandler(options:HandlerOptions):Promise<NetworkHandler>;
export function createNetworkServer(options:Omit<HandlerOptions,'store'>&{store?:NetworkStore;directory?:string}):Promise<Server>;
