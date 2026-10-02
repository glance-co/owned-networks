export interface NetworkIdentity { actorId:string; publicJwk:JsonWebKey; privateKey:CryptoKey }
export interface NetworkItem {id:string;actorId:string;createdAt:string;createdSequence:number}
export interface NetworkPost extends NetworkItem {text:string;parentId:string|null}
export interface NetworkResource extends NetworkItem {title:string;url:string;description:string}
export interface NetworkEvent extends NetworkItem {title:string;description:string;startsAt:string;endsAt:string;location:string;cancelledAt:string|null;cancellationReason:string|null;rsvps:Record<string,{response:'going'|'interested'|'not_going';updatedAt:string}>}
export interface NetworkPoll extends NetworkItem {question:string;options:string[];closesAt:string;closedAt:string|null;closeReason:string|null;votes:Record<string,{optionIndex:number;updatedAt:string}>}
export type NetworkFeedKind='posts'|'resources'|'events'|'polls';
export type NetworkFeedItem=NetworkPost|NetworkResource|NetworkEvent|NetworkPoll;
export interface PublicNetwork { protocol:string;id:string;name:string;visibility:'public';enrollment:'open'|'approval';host:string;owner:string;sequence:number;head:string;frozen:boolean;destination:string|null;posts:NetworkPost[];resources:NetworkResource[];calendarEvents:NetworkEvent[];polls:NetworkPoll[];members:Array<{actorId:string;role:'owner'|'administrator'|'member';displayName:string|null}>;pendingMembers:Array<{actorId:string;displayName:string}>;delegates:Array<{actorId:string;scopes:string[];expiresAt:string}> }
export interface PreparedNetworkWrite {event:string;creating:boolean;networkId:string;eventId:string;sequence:number;digest:string;archive?:{protocol:string;events:readonly string[]}}
export const protocol:string;
export function validateHost(value:string):string;
export function actorId(key:JsonWebKey):Promise<string>;
export function createIdentity():Promise<NetworkIdentity>;
export function exportIdentity(identity:NetworkIdentity,passphrase:string):Promise<string>;
export function importIdentity(backup:string,passphrase:string):Promise<NetworkIdentity>;
export function signCommand(identity:NetworkIdentity,state:{id:string;sequence:number;head:string|null}|null,action:string,data:unknown):Promise<string>;
export function signRead(identity:NetworkIdentity,id:string,purpose:string):Promise<string>;
export function hostRequest(host:string,path:string,options?:{payload?:unknown;token?:string;signal?:AbortSignal}):Promise<unknown>;
export function readNetwork(host:string,id:string,signal?:AbortSignal):Promise<PublicNetwork>;
export function writeNetwork(host:string,identity:NetworkIdentity,state:PublicNetwork|null,action:string,data:unknown,signal?:AbortSignal):Promise<PublicNetwork>;
export function prepareNetworkWrite(identity:NetworkIdentity,state:PublicNetwork|null,action:string,data:unknown):Promise<PreparedNetworkWrite>;
export function submitNetworkWrite(host:string,operation:PreparedNetworkWrite,signal?:AbortSignal):Promise<PublicNetwork>;
export function reconcileNetworkWrite(host:string,operation:PreparedNetworkWrite,signal?:AbortSignal):Promise<{network:PublicNetwork;accepted:boolean}>;
export function networkFeed(network:PublicNetwork,kind:NetworkFeedKind):NetworkFeedItem[];
export function pageNetworkFeed(network:PublicNetwork,kind:NetworkFeedKind,options?:{limit?:number;beforeSequence?:number|null}):{items:NetworkFeedItem[];nextCursor:string|null};
export function reportEvidence(network:PublicNetwork,kind:'post'|'resource'|'event'|'poll',id:string):string;
export function readFeed(host:string,id:string,options?:{kind?:NetworkFeedKind;cursor?:string|null;limit?:number},signal?:AbortSignal):Promise<{network:PublicNetwork;items:NetworkFeedItem[];nextCursor:string|null}>;
export function discoverNetworks(host:string,options?:{cursor?:string|null;limit?:number},signal?:AbortSignal):Promise<{networks:PublicNetwork[];nextCursor:string|null}>;
export function importNetwork(host:string,identity:NetworkIdentity,archiveText:string,signal?:AbortSignal):Promise<PublicNetwork>;
export function prepareNetworkImport(host:string,identity:NetworkIdentity,archiveText:string):Promise<PreparedNetworkWrite>;
export function verifyNetworkView(value:unknown,host:string):Promise<PublicNetwork>;
export function readReports(host:string,identity:NetworkIdentity,network:PublicNetwork,signal?:AbortSignal):Promise<Array<{id:string;reviewedText:string;reason:string;status:string}>>;
