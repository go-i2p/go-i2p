# NetDB Client/Router Isolation

## Overview

This document describes the NetDB isolation architecture that separates client and router database operations, implementing complete data isolation between I2CP clients and the router's network database.

## Architecture

### Components

1. **StdNetDB** - Base implementation that stores both RouterInfos and LeaseSets
2. **ClientNetDB** - Wrapper providing LeaseSet-only operations for clients  
3. **RouterNetDB** - Wrapper providing RouterInfo + LeaseSet operations for the router

### Isolation Strategy

- **Complete Separation**: Each I2CP client receives its own isolated `StdNetDB` instance
- **No Shared State**: Clients cannot access each other's data or the router's database
- **Type Safety**: Go's type system enforces isolation at compile time
- **Ephemeral Storage**: Client databases are in-memory only (not persisted to disk)
- **Persistent Router**: The router's NetDB is persistent and stored on disk

## Implementation Details

### ClientNetDB

**File**: `lib/netdb/client_netdb.go`

**Purpose**: Isolates client LeaseSet operations from router operations

**Operations**:
- `GetLeaseSet(hash)` - Retrieve LeaseSet by hash
- `GetLeaseSetBytes(hash)` - Get raw LeaseSet data
- `StoreLeaseSet(leaseSet)` - Store a LeaseSet
- `StoreLeaseSet2(leaseSet2)` - Store a LeaseSet2
- `GetLeaseSetCount()` - Count stored LeaseSets

**Key Design**:
```go
type ClientNetDB struct {
    db *StdNetDB  // Own isolated instance
}
```

Each session creates its own `StdNetDB` with an empty path (ephemeral):
```go
db := NewStdNetDB("")  // Empty path = in-memory only
clientDB := NewClientNetDB(db)
```

### RouterNetDB

**File**: `lib/netdb/router_netdb.go`

**Purpose**: Provide router-specific operations including floodfill functionality

**RouterInfo Operations**:
- `GetRouterInfo(hash)` - Get RouterInfo by hash
- `StoreRouterInfo(routerInfo)` - Store a RouterInfo
- `SelectPeers(count, filter)` - Select peers for tunnel building
- `SelectFloodfillRouters(count)` - Select floodfill routers
- `GetRouterInfoCount()` - Count stored RouterInfos
- `GetDatabaseSize()` - Get total database size

**LeaseSet Operations** (for direct router database operations):
- `GetLeaseSet(hash)` - Retrieve LeaseSet for floodfill, detached lookups, and direct operations
- `GetLeaseSetBytes(hash)` - Get raw LeaseSet data for network responses
- `StoreLeaseSet(leaseSet)` - Store LeaseSet from direct database store messages
- `StoreLeaseSet2(leaseSet2)` - Store LeaseSet2 from direct database store messages
- `GetLeaseSetCount()` - Count stored LeaseSets

**Key Design**:
```go
type RouterNetDB struct {
    db *StdNetDB  // Router's persistent instance
}
```

The router creates a persistent `StdNetDB` with a filesystem path:
```go
db := NewStdNetDB("/path/to/netdb")  // Persistent storage
routerDB := NewRouterNetDB(db)
```

### I2CP Session Integration

**File**: `lib/i2cp/session.go`

**Changes**: Each session now creates its own ephemeral ClientNetDB:

```go
func NewSession(id uint16, dest common.Destination, config *config.RouterConfig, _ string) (*Session, error) {
    // Create ephemeral in-memory database (empty path)
    db := NewStdNetDB("")
    
    return &Session{
        id:        id,
        dest:      dest,
        clientDB:  NewClientNetDB(db),
        // ...
    }, nil
}
```

The `netDBPath` parameter is now ignored (for backward compatibility) since all client databases are ephemeral.

## Database Message Routing

The following chart shows all possible paths for database messages and how they are handled:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DATABASE MESSAGE ROUTING                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  MESSAGE TYPE          │ SOURCE           │ CONTAINS        │ HANDLER       │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseStore         │ Network (direct) │ RouterInfo      │ RouterNetDB   │
│    (DataType=0)        │ to router        │                 │ .StoreRouter  │
│                        │                  │                 │ Info()        │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseStore         │ Network (direct) │ LeaseSet        │ RouterNetDB   │
│    (DataType=1)        │ to router        │                 │ .StoreLeaseS  │
│                        │                  │                 │ et()          │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseStore         │ Network (direct) │ LeaseSet2       │ RouterNetDB   │
│    (DataType=3)        │ to router        │                 │ .StoreLeaseS  │
│                        │                  │                 │ et2()         │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseStore         │ Client session   │ LeaseSet        │ ClientNetDB   │
│    (DataType=1)        │ via I2CP         │ (own dest)      │ .StoreLeaseS  │
│                        │                  │                 │ et()          │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseStore         │ Client session   │ LeaseSet2       │ ClientNetDB   │
│    (DataType=3)        │ via I2CP         │ (own dest)      │ .StoreLeaseS  │
│                        │                  │                 │ et2()         │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseLookup        │ Network (direct) │ Hash            │ RouterNetDB   │
│    (RouterInfo)        │ to router        │ (RouterInfo)    │ .GetRouterIn  │
│                        │                  │                 │ fo()          │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseLookup        │ Network (direct) │ Hash            │ RouterNetDB   │
│    (LeaseSet)          │ to router        │ (Destination)   │ .GetLeaseSet  │
│                        │                  │                 │ ()            │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  DatabaseLookup        │ Client session   │ Hash            │ ClientNetDB   │
│    (detached)          │ via I2CP         │ (Destination)   │ .GetLeaseSet  │
│                        │                  │                 │ ()            │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  Local Operation       │ Tunnel building  │ N/A             │ RouterNetDB   │
│    (peer selection)    │ subsystem        │                 │ .SelectPeers  │
│                        │                  │                 │ ()            │
│  ──────────────────────┼──────────────────┼─────────────────┼───────────────│
│                                                                             │
│  Local Operation       │ Floodfill        │ N/A             │ RouterNetDB   │
│    (FF selection)      │ subsystem        │                 │ .SelectFloodi │
│                        │                  │                 │ fillRouters() │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

KEY ISOLATION RULES:
  • Client sessions NEVER access RouterInfo (enforced by type system)
  • Client sessions ONLY access their own ephemeral LeaseSet storage
  • Router NEVER accesses client session databases
  • Each client session has completely isolated in-memory database
  • Router database is persistent on disk
  • Direct network messages always route to RouterNetDB
  • I2CP messages from clients route to session's ClientNetDB
```

## Benefits

1. **Security**: Clients cannot access router's RouterInfo database
2. **Privacy**: Clients cannot see each other's LeaseSets
3. **Reliability**: Client database corruption doesn't affect router or other clients
4. **Simplicity**: No complex sharing logic or synchronization needed
5. **Direct Operations**: Router can handle all direct database operations (floodfill, detached lookups, etc.) while maintaining isolation from clients

## Testing

Comprehensive test coverage in:
- `lib/netdb/client_netdb_test.go` - ClientNetDB operations and isolation
- `lib/netdb/router_netdb_test.go` - RouterNetDB operations including floodfill
- `lib/i2cp/session_test.go` - Session isolation and ephemeral storage

All tests verify:
- Correct operation of isolated databases
- Type safety enforcement
- Ephemeral vs persistent storage behavior
- Concurrent access safety
- Floodfill LeaseSet operations

## Migration Notes

### Breaking Changes

1. **NewSession signature**: The `netDBPath` parameter is now ignored
   ```go
   // Before: path was used
   session, err := NewSession(id, dest, config, "/path/to/netdb")
   
   // After: path is ignored (pass empty string)
   session, err := NewSession(id, dest, config, "")
   ```

2. **CreateSession signature**: Same as above
   ```go
   // Before
   manager.CreateSession(dest, config, "/path/to/netdb")
   
   // After: path ignored
   manager.CreateSession(dest, config, "")
   ```

### Router Integration

When initializing the router, create a RouterNetDB wrapper:

```go
// Create persistent router database
stdDB := netdb.NewStdNetDB("/path/to/router/netdb")
if err := stdDB.Create(); err != nil {
    return err
}

// Wrap in RouterNetDB for type safety
routerDB := netdb.NewRouterNetDB(stdDB)

// Use routerDB for all router operations
routerInfo := routerDB.GetRouterInfo(hash)
routerDB.StoreLeaseSet(leaseSet)  // Direct database store operation
```

## Future Enhancements

Possible improvements:
- LRU eviction for client databases to limit memory usage
- Configurable TTL for client LeaseSets
- Metrics for database sizes and operations
- Router's LeaseSet cache optimization for direct operations and detached lookups
