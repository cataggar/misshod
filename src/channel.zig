const std = @import("std");
const Protocol = @import("protocol.zig");
const build_options = @import("sshz_build_options");
const TRACE = @import("util.zig").trace;

pub const MaxChannels: u8 = build_options.channel_capacity;
pub const MaxPendingChannelData = MaxChannels * Protocol.MaxChannelDataLen;

comptime {
    if (MaxChannels == 0) {
        @compileError("channel_capacity must be greater than zero");
    }
}

pub const ChannelError = error{
    ChannelPacketTooLarge,
    ReceiveWindowExceeded,
    WindowOverflow,
    InvalidChannelReadCredit,
    ChannelReadCreditExceeded,
};

pub const ChannelLimits = struct {
    max_channels: u8 = MaxChannels,
    initial_window: u32 = Protocol.MaxChannelDataLen,
    max_window: u32 = std.math.maxInt(u32),
    packet_size: u32 = Protocol.MaxChannelDataLen,
    max_buffered_data: usize = Protocol.MaxChannelDataLen,
};

pub const ClientChannelOpenMode = enum {
    AutoShell,
    AutoExec,
    RawSession,
};

pub const ChannelType = enum {
    Session,
    DirectTcpip,
    ForwardedTcpip,

    pub fn name(self: ChannelType) []const u8 {
        return switch (self) {
            .Session => "session",
            .DirectTcpip => "direct-tcpip",
            .ForwardedTcpip => "forwarded-tcpip",
        };
    }

    pub fn fromName(channel_name: []const u8) ?ChannelType {
        if (std.mem.eql(u8, channel_name, "session")) return .Session;
        if (std.mem.eql(u8, channel_name, "direct-tcpip")) return .DirectTcpip;
        if (std.mem.eql(u8, channel_name, "forwarded-tcpip")) return .ForwardedTcpip;
        return null;
    }

    pub fn hasTcpipOpenPayload(self: ChannelType) bool {
        return switch (self) {
            .Session => false,
            .DirectTcpip, .ForwardedTcpip => true,
        };
    }
};

pub const TcpipOpen = struct {
    host: []const u8 = "",
    port: u32 = 0,
    originator_host: []const u8 = "",
    originator_port: u32 = 0,
};

pub const ChannelState = enum {
    OpenWrite,
    Open,
    /// Inbound open awaiting acceptance or rejection; also the fail-closed allocation default.
    OpenPending,
    OpenSent,
    ConfirmWrite,
    RspWrite,
    RspFailureWrite,
    Connected,
    Data,
    DataRx,
    DataTx,
    DataTxComplete,
    EofWrite,
    CloseWrite,
    Closed,
    OpenFailureWrite,
};

pub const ChannelKind = enum {
    Session,
    AgentForward,
};

pub const ChannelControl = enum {
    Eof,
    Close,
};

pub const Channel = struct {
    const Self = @This();

    kind: ChannelKind,
    local_id: u32,
    remote_id: u32,
    remote_id_known: bool,
    peer_window: u32,
    remote_max_packet_size: u32,
    local_window: u32,
    local_window_target: u32,
    local_max_packet_size: u32,
    max_buffered_data: usize,
    automatic_read_credit: bool,
    delivered_uncredited: u32,
    pending_window_adjust: u32,
    // Mutate only through ChannelTable's resize queue helpers.
    pending_window_change: ?[4]u32 = null,
    write_buf: [Protocol.MaxChannelDataLen]u8 = undefined,
    write_buf_nbytes: usize,
    tx_in_flight_len: usize,
    write_data_type: ?u32 = null,
    server_exit_submitted: bool = false,
    server_exit_pending: bool = false,
    eof_pending: bool,
    close_pending: bool,
    control_in_flight: ?ChannelControl,
    eof_sent: bool,
    eof_received: bool,
    close_sent: bool,
    close_received: bool,
    client_open_mode: ClientChannelOpenMode,
    channel_type: ChannelType,
    tcpip_open: TcpipOpen,
    open_failure_reason_code: u32,
    open_failure_description: []const u8,
    state: ChannelState,

    pub fn init(local_id: u32, remote_id: u32, peer_window: u32, remote_max_packet_size: u32) Self {
        return Self.initKind(.Session, local_id, remote_id, true, peer_window, remote_max_packet_size, .{});
    }

    pub fn initKind(
        kind: ChannelKind,
        local_id: u32,
        remote_id: u32,
        remote_id_known: bool,
        peer_window: u32,
        remote_max_packet_size: u32,
        limits: ChannelLimits,
    ) Self {
        return Self{
            .kind = kind,
            .local_id = local_id,
            .remote_id = remote_id,
            .remote_id_known = remote_id_known,
            .peer_window = peer_window,
            .remote_max_packet_size = remote_max_packet_size,
            .local_window = limits.initial_window,
            .local_window_target = limits.initial_window,
            .local_max_packet_size = limits.packet_size,
            .max_buffered_data = limits.max_buffered_data,
            .automatic_read_credit = true,
            .delivered_uncredited = 0,
            .pending_window_adjust = 0,
            .write_buf_nbytes = 0,
            .tx_in_flight_len = 0,
            .eof_pending = false,
            .close_pending = false,
            .control_in_flight = null,
            .eof_sent = false,
            .eof_received = false,
            .close_sent = false,
            .close_received = false,
            .client_open_mode = .RawSession,
            .channel_type = .Session,
            .tcpip_open = .{},
            .open_failure_reason_code = 4,
            .open_failure_description = "too many channels",
            .state = .OpenPending,
        };
    }

    pub fn secureZero(self: *Self) void {
        std.crypto.secureZero(u8, &self.write_buf);
    }

    pub fn consumeWriteBuffer(self: *Self, sent: usize) void {
        std.debug.assert(sent <= self.write_buf_nbytes);
        const remaining = self.write_buf_nbytes - sent;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.write_buf[0..remaining], self.write_buf[sent..self.write_buf_nbytes]);
        }
        std.crypto.secureZero(u8, self.write_buf[remaining..self.write_buf_nbytes]);
        self.write_buf_nbytes = remaining;
    }

    pub fn discardWriteBuffer(self: *Self) void {
        std.crypto.secureZero(u8, self.write_buf[0..self.write_buf_nbytes]);
        self.write_buf_nbytes = 0;
        self.tx_in_flight_len = 0;
    }

    pub fn discardUnframedWriteBuffer(self: *Self) usize {
        std.debug.assert(self.tx_in_flight_len <= self.write_buf_nbytes);
        const discarded = self.write_buf_nbytes - self.tx_in_flight_len;
        std.crypto.secureZero(u8, self.write_buf[self.tx_in_flight_len..self.write_buf_nbytes]);
        self.write_buf_nbytes = self.tx_in_flight_len;
        return discarded;
    }

    pub fn eofFlushed(self: *const Self) bool {
        return self.eof_sent and !self.eof_pending and
            self.write_buf_nbytes == 0 and self.tx_in_flight_len == 0 and
            self.control_in_flight == null;
    }

    pub fn expectsOpenReply(self: *const Self) bool {
        return self.state == .OpenSent;
    }

    fn establishedForReceive(self: *const Self) bool {
        if (!self.remote_id_known) return false;
        return switch (self.state) {
            // Confirmed outbound `.Open` channels may receive during automatic
            // setup. Undecided inbound opens are explicitly `.OpenPending`.
            .Open, .Connected, .Data, .DataRx, .DataTx, .DataTxComplete, .RspWrite, .RspFailureWrite, .EofWrite, .CloseWrite => true,
            .OpenPending, .OpenWrite, .OpenSent, .ConfirmWrite, .Closed, .OpenFailureWrite => false,
        };
    }

    pub fn canReceiveDataPacket(self: *const Self) bool {
        // `.Data` is accepted alongside `.DataRx` because a rekey may service
        // the next packet before `advanceChannel` normalizes a cleared data
        // event from `.Data` back to `.DataRx`. Both are established states,
        // so this widens the window only for channels already carrying data.
        return self.establishedForReceive() and
            (self.state == .DataRx or self.state == .Data) and
            !self.close_received;
    }

    pub fn canReceiveEofPacket(self: *const Self) bool {
        return self.establishedForReceive() and !self.close_received;
    }

    pub fn canReceiveClosePacket(self: *const Self) bool {
        return self.establishedForReceive() and !self.close_received;
    }

    pub fn canReceiveRequestPacket(self: *const Self) bool {
        return self.establishedForReceive();
    }

    pub fn canReceiveWindowAdjustPacket(self: *const Self) bool {
        return self.establishedForReceive() and !self.close_received;
    }

    /// Outbound requests wait for setup, unlike traffic received after open
    /// confirmation. EOF alone does not close the channel's request direction.
    pub fn canSendChannelRequest(self: *const Self) bool {
        if (!self.remote_id_known or self.close_pending or self.close_sent or self.close_received) return false;
        return switch (self.state) {
            .Connected, .Data, .DataRx, .DataTx, .DataTxComplete => true,
            .OpenWrite, .Open, .OpenPending, .OpenSent, .ConfirmWrite, .RspWrite, .RspFailureWrite, .EofWrite, .CloseWrite, .Closed, .OpenFailureWrite => false,
        };
    }

    /// A queued automatic resize may survive outbound setup or an EOF write,
    /// but never rejection, close, or reuse as a non-session channel.
    pub fn canRetainWindowChange(self: *const Self) bool {
        if (self.kind != .Session or self.channel_type != .Session or
            self.close_pending or self.close_sent or self.close_received) return false;
        if (self.canSendChannelRequest()) return true;
        return switch (self.state) {
            .OpenWrite, .OpenSent, .Open, .RspWrite => self.client_open_mode != .RawSession,
            .EofWrite => self.remote_id_known,
            else => false,
        };
    }

    pub fn consumeLocalWindow(self: *Self, len: usize) ChannelError!void {
        if (len > self.local_max_packet_size) return error.ChannelPacketTooLarge;
        if (len > self.local_window) return error.ReceiveWindowExceeded;
        self.local_window -= @intCast(len);
    }

    pub fn consumeReceivedData(self: *Self, len: usize) ChannelError!void {
        if (!self.automatic_read_credit and
            len > std.math.maxInt(u32) - self.delivered_uncredited)
        {
            return error.WindowOverflow;
        }
        try self.consumeLocalWindow(len);
        if (!self.automatic_read_credit) {
            self.delivered_uncredited += @intCast(len);
        }
    }

    pub fn queueReadCredit(self: *Self, count: usize) ChannelError!void {
        if (count == 0 or count > std.math.maxInt(u32)) {
            return error.InvalidChannelReadCredit;
        }
        const amount: u32 = @intCast(count);
        if (amount > self.delivered_uncredited) {
            return error.ChannelReadCreditExceeded;
        }
        if (amount > std.math.maxInt(u32) - self.pending_window_adjust) {
            return error.WindowOverflow;
        }
        if (self.local_window > self.local_window_target) {
            return error.WindowOverflow;
        }
        const available = self.local_window_target - self.local_window;
        if (self.pending_window_adjust > available or
            amount > available - self.pending_window_adjust)
        {
            return error.WindowOverflow;
        }
        self.delivered_uncredited -= amount;
        self.pending_window_adjust += amount;
    }

    pub fn adjustPeerWindow(self: *Self, amount: u32, maximum: u32) ChannelError!void {
        if (self.peer_window > maximum or amount > maximum - self.peer_window)
            return error.WindowOverflow;
        self.peer_window += amount;
    }

    /// Returns true when automatic replenishment is due or manual credit is queued.
    pub fn needsWindowAdjust(self: *const Self) bool {
        if (!self.automatic_read_credit) return self.pending_window_adjust != 0;
        return self.local_window == 0 or self.local_window < self.local_window_target / 2;
    }

    /// Returns the automatic replenishment or application-credited byte count.
    pub fn windowAdjustAmount(self: *const Self) u32 {
        if (!self.automatic_read_credit) return self.pending_window_adjust;
        return self.local_window_target - self.local_window;
    }

    pub fn applyWindowAdjust(self: *Self, amount: u32) void {
        std.debug.assert(amount != 0);
        std.debug.assert(amount <= self.local_window_target - self.local_window);
        self.local_window += amount;
        if (!self.automatic_read_credit) {
            std.debug.assert(amount <= self.pending_window_adjust);
            self.pending_window_adjust -= amount;
        }
    }
};

pub const ChannelTable = struct {
    const Self = @This();

    channels: [MaxChannels]?Channel = .{null} ** MaxChannels,
    next_local_id: u32 = 0,
    last_serviced_slot: usize = 0,
    last_window_change_slot: usize = 0,
    pending_window_change_count: u8 = 0,
    limits: ChannelLimits = .{},

    pub fn allocChannel(self: *Self, remote_id: u32, peer_window: u32, remote_max_packet_size: u32) ?*Channel {
        return self.allocChannelKindKnown(.Session, remote_id, true, peer_window, remote_max_packet_size);
    }

    pub fn allocOutboundChannel(self: *Self) ?*Channel {
        return self.allocChannelKindKnown(.Session, 0, false, 0, 0);
    }

    pub fn allocOutboundChannelKind(self: *Self, kind: ChannelKind) ?*Channel {
        return self.allocChannelKindKnown(kind, 0, false, 0, 0);
    }

    pub fn allocChannelKind(
        self: *Self,
        kind: ChannelKind,
        remote_id: u32,
        peer_window: u32,
        remote_max_packet_size: u32,
    ) ?*Channel {
        return self.allocChannelKindKnown(kind, remote_id, true, peer_window, remote_max_packet_size);
    }

    fn allocChannelKindKnown(
        self: *Self,
        kind: ChannelKind,
        remote_id: u32,
        remote_id_known: bool,
        peer_window: u32,
        remote_max_packet_size: u32,
    ) ?*Channel {
        const local_id = self.next_local_id;
        for (&self.channels, 0..) |*slot, index| {
            if (index >= self.limits.max_channels) break;
            if (slot.* == null) {
                slot.* = Channel.initKind(kind, local_id, remote_id, remote_id_known, peer_window, remote_max_packet_size, self.limits);
                self.next_local_id +%= 1;
                return &(slot.*.?);
            }
        }
        return null; // table full
    }

    pub fn findByLocalId(self: *Self, local_id: u32) ?*Channel {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                if (ch.local_id == local_id) return ch;
            }
        }
        return null;
    }

    pub fn findByRemoteId(self: *Self, remote_id: u32) ?*Channel {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                if (ch.remote_id == remote_id) return ch;
            }
        }
        return null;
    }

    pub fn freeChannel(self: *Self, local_id: u32) void {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                if (ch.local_id == local_id) {
                    self.discardPendingWindowChange(ch);
                    ch.secureZero();
                    slot.* = null;
                    return;
                }
            }
        }
    }

    pub fn activeCount(self: *const Self) u32 {
        var count: u32 = 0;
        for (self.channels) |slot| {
            if (slot != null) count += 1;
        }
        return count;
    }

    pub fn secureZeroAll(self: *Self) void {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                self.discardPendingWindowChange(ch);
                ch.secureZero();
                slot.* = null;
            }
        }
        std.debug.assert(self.pending_window_change_count == 0);
    }

    fn isRunnable(state: ChannelState) bool {
        return switch (state) {
            .OpenWrite, .ConfirmWrite, .RspWrite, .RspFailureWrite, .CloseWrite, .OpenFailureWrite, .EofWrite => true,
            .Connected => true,
            .Data => true,
            .DataTx, .DataTxComplete => true,
            .DataRx, .Open, .OpenPending, .OpenSent, .Closed => false,
        };
    }

    /// Find the next channel that has pending work, using round-robin
    /// starting after `last_serviced_slot` to ensure fairness.
    pub fn findNextRunnable(self: *Self) ?*Channel {
        var i: usize = 0;
        while (i < MaxChannels) : (i += 1) {
            const slot_idx = (self.last_serviced_slot + 1 + i) % MaxChannels;
            if (self.channels[slot_idx]) |*ch| {
                const tx_ready = ch.remote_id_known and ch.write_buf_nbytes > 0 and ch.tx_in_flight_len == 0 and ch.peer_window > 0;
                const control_ready = ch.remote_id_known and ch.write_buf_nbytes == 0 and ch.tx_in_flight_len == 0 and
                    ch.control_in_flight == null and
                    (ch.server_exit_pending or (ch.eof_pending and !ch.eof_sent) or (ch.close_pending and !ch.close_sent));
                const terminal_close_ready = ch.remote_id_known and ch.tx_in_flight_len == 0 and ch.close_pending and !ch.close_sent;
                const window_adjust_ready = ch.remote_id_known and ch.state == .DataRx and
                    !ch.eof_received and !ch.close_pending and !ch.close_sent and !ch.close_received and
                    ch.needsWindowAdjust();
                if (tx_ready or control_ready or terminal_close_ready or window_adjust_ready or isRunnable(ch.state)) {
                    self.last_serviced_slot = slot_idx;
                    return ch;
                }
            }
        }
        return null;
    }

    pub fn findNextDeferredWrite(self: *Self) ?*Channel {
        var i: usize = 0;
        while (i < MaxChannels) : (i += 1) {
            const slot_idx = (self.last_serviced_slot + 1 + i) % MaxChannels;
            if (self.channels[slot_idx]) |*ch| {
                const tx_ready = ch.remote_id_known and ch.write_buf_nbytes > 0 and ch.tx_in_flight_len == 0 and ch.peer_window > 0;
                const control_ready = ch.remote_id_known and ch.write_buf_nbytes == 0 and ch.tx_in_flight_len == 0 and
                    ch.control_in_flight == null and
                    (ch.server_exit_pending or (ch.eof_pending and !ch.eof_sent) or (ch.close_pending and !ch.close_sent));
                const terminal_close_ready = ch.remote_id_known and ch.tx_in_flight_len == 0 and ch.close_pending and !ch.close_sent;
                const window_adjust_ready = ch.remote_id_known and ch.state == .DataRx and
                    !ch.eof_received and !ch.close_pending and !ch.close_sent and !ch.close_received and
                    ch.needsWindowAdjust();
                if (tx_ready or control_ready or terminal_close_ready or window_adjust_ready or
                    (ch.close_received and !ch.close_sent))
                {
                    self.last_serviced_slot = slot_idx;
                    return ch;
                }
            }
        }
        return null;
    }

    pub fn findNextWindowAdjust(self: *Self) ?*Channel {
        var i: usize = 0;
        while (i < MaxChannels) : (i += 1) {
            const slot_idx = (self.last_serviced_slot + 1 + i) % MaxChannels;
            if (self.channels[slot_idx]) |*ch| {
                if (ch.remote_id_known and (ch.state == .Data or ch.state == .DataRx) and
                    !ch.eof_received and !ch.close_pending and !ch.close_sent and !ch.close_received and
                    ch.needsWindowAdjust())
                {
                    self.last_serviced_slot = slot_idx;
                    return ch;
                }
            }
        }
        return null;
    }

    pub fn hasPendingWindowChanges(self: *const Self) bool {
        return self.pending_window_change_count != 0;
    }

    /// All resize mutations use these helpers so the count includes each
    /// table-owned channel exactly once, regardless of coalescing or readiness.
    pub fn queueWindowChange(self: *Self, channel: *Channel, size: [4]u32) void {
        if (channel.pending_window_change == null) {
            std.debug.assert(self.pending_window_change_count < self.limits.max_channels);
            self.pending_window_change_count += 1;
        }
        channel.pending_window_change = size;
    }

    pub fn takePendingWindowChange(self: *Self, channel: *Channel) ?[4]u32 {
        const size = channel.pending_window_change orelse return null;
        std.debug.assert(self.pending_window_change_count != 0);
        self.pending_window_change_count -= 1;
        channel.pending_window_change = null;
        return size;
    }

    pub fn discardPendingWindowChange(self: *Self, channel: *Channel) void {
        if (self.takePendingWindowChange(channel) != null) {
            TRACE(.Debug, "discarding queued window-change for obsolete channel {d}", .{channel.local_id});
        }
    }

    pub fn discardAllPendingWindowChanges(self: *Self) void {
        if (!self.hasPendingWindowChanges()) return;
        for (&self.channels) |*slot| {
            if (slot.*) |*channel| self.discardPendingWindowChange(channel);
        }
        std.debug.assert(self.pending_window_change_count == 0);
    }

    /// Empty queues never inspect channel slots. When work exists, resize
    /// fairness is independent of the data/control scheduler's cursor.
    /// A channel waiting for setup or a write cannot block another's resize.
    pub fn findNextWindowChange(self: *Self) ?*Channel {
        if (!self.hasPendingWindowChanges()) return null;
        const capacity: usize = self.limits.max_channels;
        for (0..capacity) |i| {
            const slot_idx = (self.last_window_change_slot + 1 + i) % capacity;
            if (self.channels[slot_idx]) |*ch| {
                if (ch.pending_window_change == null) continue;
                if (!ch.canRetainWindowChange()) {
                    self.discardPendingWindowChange(ch);
                    if (!self.hasPendingWindowChanges()) return null;
                    continue;
                }
                if (ch.canSendChannelRequest() and ch.tx_in_flight_len == 0) {
                    self.last_window_change_slot = slot_idx;
                    return ch;
                }
            }
        }
        return null;
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "empty resize summary never reads channel slots" {
    comptime {
        // Undefined storage makes any accidental slot probe a compile error.
        var table = ChannelTable{ .channels = undefined, .limits = .{ .max_channels = 1 } };
        std.debug.assert(!table.hasPendingWindowChanges());
        std.debug.assert(table.findNextWindowChange() == null);
        table.discardAllPendingWindowChanges();
    }
}

fn expectResizeSummaryForTest(table: *const ChannelTable, expected: u8) !void {
    var actual: usize = 0;
    for (table.channels) |slot| {
        if (slot) |channel| {
            if (channel.pending_window_change != null) actual += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, expected), actual);
    try std.testing.expectEqual(expected, table.pending_window_change_count);
    try std.testing.expectEqual(expected != 0, table.hasPendingWindowChanges());
}

test "resize summary tracks coalescing framing discard release and reset" {
    var table = ChannelTable{ .limits = .{ .max_channels = 2 } };
    try expectResizeSummaryForTest(&table, 0);
    const first = table.allocChannel(100, 32768, 32768).?;
    first.state = .DataRx;
    const second = table.allocChannel(200, 32768, 32768).?;
    second.state = .DataRx;
    table.queueWindowChange(first, .{ 80, 24, 0, 0 });
    try expectResizeSummaryForTest(&table, 1);
    table.queueWindowChange(first, .{ 120, 40, 960, 640 });
    try expectResizeSummaryForTest(&table, 1);
    table.queueWindowChange(second, .{ 90, 25, 720, 400 });
    try expectResizeSummaryForTest(&table, 2);
    try std.testing.expect(table.findNextWindowChange().? == second);
    try expectResizeSummaryForTest(&table, 2);
    try std.testing.expectEqualDeep(@as(?[4]u32, .{ 90, 25, 720, 400 }), table.takePendingWindowChange(second));
    try expectResizeSummaryForTest(&table, 1);
    try std.testing.expect(table.takePendingWindowChange(second) == null);
    try expectResizeSummaryForTest(&table, 1);
    const first_id = first.local_id;
    table.freeChannel(second.local_id);
    try expectResizeSummaryForTest(&table, 1);
    table.freeChannel(first_id);
    table.freeChannel(first_id);
    try expectResizeSummaryForTest(&table, 0);

    const replacement = table.allocChannel(300, 32768, 32768).?;
    replacement.state = .DataRx;
    try std.testing.expect(replacement.local_id != first_id);
    try std.testing.expect(replacement.pending_window_change == null);
    for ([_]ChannelState{ .Closed, .OpenFailureWrite, .OpenPending }) |obsolete| {
        replacement.state = .DataRx;
        table.queueWindowChange(replacement, .{ 120, 40, 960, 640 });
        try expectResizeSummaryForTest(&table, 1);
        replacement.state = obsolete;
        try std.testing.expect(table.findNextWindowChange() == null);
        try expectResizeSummaryForTest(&table, 0);
    }
    replacement.state = .DataRx;
    table.queueWindowChange(replacement, .{ 80, 24, 0, 0 });
    table.discardPendingWindowChange(replacement);
    table.discardPendingWindowChange(replacement);
    try expectResizeSummaryForTest(&table, 0);
    const other = table.allocChannel(400, 32768, 32768).?;
    other.state = .DataRx;
    table.queueWindowChange(replacement, .{ 80, 24, 0, 0 });
    table.queueWindowChange(other, .{ 90, 25, 720, 400 });
    table.discardAllPendingWindowChanges();
    table.discardAllPendingWindowChanges();
    try expectResizeSummaryForTest(&table, 0);
    table.queueWindowChange(replacement, .{ 80, 24, 0, 0 });
    table.queueWindowChange(other, .{ 90, 25, 720, 400 });
    table.secureZeroAll();
    try expectResizeSummaryForTest(&table, 0);
    try std.testing.expectEqual(@as(u32, 0), table.activeCount());
    const after_reset = table.allocChannel(500, 32768, 32768).?;
    table.queueWindowChange(after_reset, .{ 80, 24, 0, 0 });
    try expectResizeSummaryForTest(&table, 1);
    _ = table.takePendingWindowChange(after_reset);
    try expectResizeSummaryForTest(&table, 0);
}

test "resize summary spans compiled capacity and honors a lower runtime limit" {
    const table = try std.testing.allocator.create(ChannelTable);
    defer std.testing.allocator.destroy(table);
    table.* = .{};
    for (0..MaxChannels) |index| {
        const channel = table.allocChannel(@intCast(index), 32768, 32768).?;
        channel.state = .DataRx;
        table.queueWindowChange(channel, .{ 80, 24, 0, 0 });
        table.queueWindowChange(channel, .{ 120, 40, 960, 640 });
        try expectResizeSummaryForTest(table, @intCast(index + 1));
    }
    for (0..MaxChannels) |index| {
        const channel = table.findNextWindowChange().?;
        try std.testing.expectEqual(@as(u32, @intCast((index + 1) % MaxChannels)), channel.local_id);
        _ = table.takePendingWindowChange(channel);
        try expectResizeSummaryForTest(table, @intCast(MaxChannels - index - 1));
    }
    try std.testing.expect(table.findNextWindowChange() == null);
    table.secureZeroAll();
    table.limits.max_channels = 1;
    const only = table.allocChannel(1000, 32768, 32768).?;
    only.state = .DataRx;
    table.last_window_change_slot = MaxChannels - 1;
    table.queueWindowChange(only, .{ 80, 24, 0, 0 });
    try std.testing.expect(table.findNextWindowChange().? == only);
    try expectResizeSummaryForTest(table, 1);
    table.discardPendingWindowChange(only);
    try expectResizeSummaryForTest(table, 0);
    try std.testing.expect(table.findNextWindowChange() == null);
}

test "outbound channel requests wait for setup without restricting confirmed receive" {
    var channel = Channel.init(0, 42, 32768, 32768);
    channel.client_open_mode = .AutoShell;
    inline for (std.meta.tags(ChannelState)) |state| {
        channel.state = state;
        const ready = switch (state) {
            .Connected, .Data, .DataRx, .DataTx, .DataTxComplete => true,
            else => false,
        };
        try std.testing.expectEqual(ready, channel.canSendChannelRequest());
        channel.remote_id_known = false;
        try std.testing.expect(!channel.canSendChannelRequest());
        channel.remote_id_known = true;
    }
    channel.state = .OpenPending;
    try std.testing.expect(!channel.canRetainWindowChange());
    channel.state = .Open;
    try std.testing.expect(channel.canReceiveRequestPacket());
    try std.testing.expect(!channel.canSendChannelRequest());
    try std.testing.expect(channel.canRetainWindowChange());
    channel.state = .DataRx;
    inline for (.{ "close_pending", "close_sent", "close_received" }) |field| {
        @field(channel, field) = true;
        try std.testing.expect(!channel.canSendChannelRequest());
        try std.testing.expect(!channel.canRetainWindowChange());
        @field(channel, field) = false;
    }
    channel.eof_sent = true;
    channel.eof_received = true;
    try std.testing.expect(channel.canSendChannelRequest());
}

test "pending resize storage follows channel capacity and resets on slot release" {
    var table = ChannelTable{ .limits = .{ .max_channels = 2 } };
    for (0..2) |index| {
        const channel = table.allocChannel(@intCast(100 + index), 32768, 32768).?;
        channel.state = .DataRx;
        table.queueWindowChange(channel, .{ 80, 24, 0, 0 });
    }
    try std.testing.expect(table.allocChannel(300, 32768, 32768) == null);
    const channel = table.findByLocalId(0).?;
    table.queueWindowChange(channel, .{ 120, 40, 960, 640 });
    try std.testing.expectEqualDeep(@as(?[4]u32, .{ 80, 24, 0, 0 }), table.findByLocalId(1).?.pending_window_change);
    table.freeChannel(0);
    const replacement = table.allocChannel(300, 32768, 32768).?;
    try std.testing.expect(replacement.pending_window_change == null);
    try std.testing.expectEqual(@as(u32, 1), table.findNextWindowChange().?.local_id);
}

test "allocChannel assigns monotonic local IDs" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(100, 32768, 32768).?;
    try std.testing.expectEqual(@as(u32, 0), ch0.local_id);
    try std.testing.expectEqual(@as(u32, 100), ch0.remote_id);

    const ch1 = table.allocChannel(200, 32768, 32768).?;
    try std.testing.expectEqual(@as(u32, 1), ch1.local_id);

    try std.testing.expectEqual(@as(u32, 2), table.activeCount());
}

test "findByLocalId and findByRemoteId" {
    var table = ChannelTable{};
    _ = table.allocChannel(100, 32768, 32768);
    _ = table.allocChannel(200, 16384, 16384);

    const found = table.findByLocalId(1).?;
    try std.testing.expectEqual(@as(u32, 200), found.remote_id);

    const found2 = table.findByRemoteId(100).?;
    try std.testing.expectEqual(@as(u32, 0), found2.local_id);

    try std.testing.expect(table.findByLocalId(99) == null);
    try std.testing.expect(table.findByRemoteId(999) == null);
}

test "freeChannel removes channel and allows reuse of slot" {
    var table = ChannelTable{};
    _ = table.allocChannel(100, 32768, 32768);
    _ = table.allocChannel(200, 32768, 32768);
    try std.testing.expectEqual(@as(u32, 2), table.activeCount());

    table.freeChannel(0);
    try std.testing.expectEqual(@as(u32, 1), table.activeCount());
    try std.testing.expect(table.findByLocalId(0) == null);

    // slot is reused but ID continues monotonically
    const ch = table.allocChannel(300, 32768, 32768).?;
    try std.testing.expectEqual(@as(u32, 2), ch.local_id);
}

test "allocChannel returns null when table is full" {
    var table = ChannelTable{};
    var i: u32 = 0;
    while (i < MaxChannels) : (i += 1) {
        try std.testing.expect(table.allocChannel(i + 100, 32768, 32768) != null);
    }
    try std.testing.expect(table.allocChannel(999, 32768, 32768) == null);
}

test "Channel init sets default values" {
    const ch = Channel.init(0, 42, 65535, 32768);
    try std.testing.expectEqual(ChannelKind.Session, ch.kind);
    try std.testing.expectEqual(@as(u32, 0), ch.local_id);
    try std.testing.expectEqual(@as(u32, 42), ch.remote_id);
    try std.testing.expectEqual(@as(u32, 65535), ch.peer_window);
    try std.testing.expectEqual(@as(u32, 32768), ch.remote_max_packet_size);
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, ch.local_window);
    try std.testing.expectEqual(@as(usize, 0), ch.write_buf_nbytes);
    try std.testing.expect(!ch.eof_sent);
    try std.testing.expect(!ch.eof_received);
    try std.testing.expect(!ch.close_sent);
    try std.testing.expect(!ch.close_received);
    try std.testing.expectEqual(ClientChannelOpenMode.RawSession, ch.client_open_mode);
    try std.testing.expectEqual(ChannelType.Session, ch.channel_type);
    try std.testing.expectEqualStrings("", ch.tcpip_open.host);
    try std.testing.expectEqual(@as(u32, 0), ch.tcpip_open.port);
    try std.testing.expectEqualStrings("", ch.tcpip_open.originator_host);
    try std.testing.expectEqual(@as(u32, 0), ch.tcpip_open.originator_port);
    try std.testing.expectEqual(@as(u32, 4), ch.open_failure_reason_code);
    try std.testing.expectEqualStrings("too many channels", ch.open_failure_description);
    try std.testing.expectEqual(ChannelState.OpenPending, ch.state);
}

test "pending inbound opens are non-receiving and idle regardless of outbound mode" {
    for (std.enums.values(ClientChannelOpenMode)) |mode| {
        var table = ChannelTable{};
        const ch = table.allocChannel(42, 32768, 4096).?;
        ch.client_open_mode = mode;
        try std.testing.expectEqual(ChannelState.OpenPending, ch.state);
        try std.testing.expect(ch.remote_id_known);
        try std.testing.expect(!ch.expectsOpenReply());
        try std.testing.expect(!ch.canReceiveDataPacket());
        try std.testing.expect(!ch.canReceiveEofPacket());
        try std.testing.expect(!ch.canReceiveClosePacket());
        try std.testing.expect(!ch.canReceiveRequestPacket());
        try std.testing.expect(!ch.canReceiveWindowAdjustPacket());

        ch.local_window = 0;
        try std.testing.expect(ch.needsWindowAdjust());
        try std.testing.expect(table.findNextRunnable() == null);
        try std.testing.expect(table.findNextDeferredWrite() == null);
        try std.testing.expect(table.findNextWindowAdjust() == null);

        ch.state = .Open;
        try std.testing.expect(ch.canReceiveEofPacket());
        try std.testing.expect(ch.canReceiveClosePacket());
        try std.testing.expect(ch.canReceiveRequestPacket());
        try std.testing.expect(ch.canReceiveWindowAdjustPacket());
        try std.testing.expect(!ch.canReceiveDataPacket());

        ch.remote_id_known = false;
        try std.testing.expect(!ch.canReceiveEofPacket());
        try std.testing.expect(!ch.canReceiveClosePacket());
        try std.testing.expect(!ch.canReceiveRequestPacket());
        try std.testing.expect(!ch.canReceiveWindowAdjustPacket());
    }
}

test "ChannelType maps SSH names" {
    try std.testing.expectEqual(ChannelType.Session, ChannelType.fromName("session").?);
    try std.testing.expectEqual(ChannelType.DirectTcpip, ChannelType.fromName("direct-tcpip").?);
    try std.testing.expectEqual(ChannelType.ForwardedTcpip, ChannelType.fromName("forwarded-tcpip").?);
    try std.testing.expect(ChannelType.fromName("x11") == null);
    try std.testing.expectEqualStrings("direct-tcpip", ChannelType.DirectTcpip.name());
    try std.testing.expect(ChannelType.DirectTcpip.hasTcpipOpenPayload());
    try std.testing.expect(!ChannelType.Session.hasTcpipOpenPayload());
}

test "allocChannelKind preserves channel kind" {
    var table = ChannelTable{};
    const ch = table.allocChannelKind(.AgentForward, 10, 32768, 32768).?;
    try std.testing.expectEqual(ChannelKind.AgentForward, ch.kind);
    try std.testing.expectEqual(@as(u32, 0), ch.local_id);
}

test "closing one channel does not affect another" {
    var table = ChannelTable{};
    _ = table.allocChannel(100, 32768, 32768);
    const ch1 = table.allocChannel(200, 16384, 16384).?;
    ch1.state = .DataRx;

    table.freeChannel(0);
    try std.testing.expectEqual(@as(u32, 1), table.activeCount());

    const remaining = table.findByLocalId(1).?;
    try std.testing.expectEqual(@as(u32, 200), remaining.remote_id);
    try std.testing.expectEqual(ChannelState.DataRx, remaining.state);
}

test "per-channel window management is independent" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 1000, 32768).?;
    const ch1 = table.allocChannel(20, 5000, 32768).?;

    try std.testing.expectEqual(@as(u32, 1000), ch0.peer_window);
    try std.testing.expectEqual(@as(u32, 5000), ch1.peer_window);

    ch0.peer_window +|= 2000;
    try std.testing.expectEqual(@as(u32, 3000), ch0.peer_window);
    try std.testing.expectEqual(@as(u32, 5000), ch1.peer_window);
}

test "secureZeroAll clears all channels" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    ch0.write_buf[0] = 0xAA;
    _ = table.allocChannel(20, 32768, 32768);

    table.secureZeroAll();
    try std.testing.expectEqual(@as(u32, 0), table.activeCount());
}

test "findNextRunnable round-robin alternates between two runnable channels" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    const ch1 = table.allocChannel(20, 32768, 32768).?;
    ch0.state = .Data;
    ch1.state = .Data;

    // First call should return one channel
    const first = table.findNextRunnable().?;
    const first_id = first.local_id;

    // Second call should return the other channel
    const second = table.findNextRunnable().?;
    const second_id = second.local_id;

    try std.testing.expect(first_id != second_id);

    // Third call wraps back to the first
    const third = table.findNextRunnable().?;
    try std.testing.expectEqual(first_id, third.local_id);
}

test "findNextRunnable returns single runnable regardless of cursor" {
    var table = ChannelTable{};
    _ = table.allocChannel(10, 32768, 32768); // slot 0, state OpenPending (not runnable)
    const ch1 = table.allocChannel(20, 32768, 32768).?; // slot 1
    ch1.state = .Data;

    // Should always find ch1
    const r1 = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 1), r1.local_id);

    const r2 = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 1), r2.local_id);
}

test "findNextRunnable skips freed slots" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    ch0.state = .Data;
    const ch1 = table.allocChannel(20, 32768, 32768).?;
    ch1.state = .Data;

    // Service ch0 first
    _ = table.findNextRunnable();

    // Free ch0
    table.freeChannel(0);

    // Should find ch1
    const r = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 1), r.local_id);
}

test "findNextRunnable wraps from last slot to slot 0" {
    var table = ChannelTable{};
    // Fill all slots
    var i: u32 = 0;
    while (i < MaxChannels) : (i += 1) {
        const ch = table.allocChannel(i + 100, 32768, 32768).?;
        ch.state = .DataRx; // not runnable
    }
    // Make only slot 0 runnable
    table.channels[0].?.state = .Data;
    // Set cursor to last slot so next scan wraps to 0
    table.last_serviced_slot = MaxChannels - 1;

    const r = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 0), r.local_id);
    try std.testing.expectEqual(@as(usize, 0), table.last_serviced_slot);
}

test "findNextRunnable returns null when no channels runnable" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    ch0.state = .DataRx;
    const ch1 = table.allocChannel(20, 32768, 32768).?;
    ch1.state = .DataRx;
    try std.testing.expect(table.findNextRunnable() == null);
}

test "findNextRunnable wakes a receive-only channel needing window adjustment" {
    var table = ChannelTable{ .limits = .{ .initial_window = 12, .packet_size = 4 } };
    const ch = table.allocChannel(10, 12, 4).?;
    ch.state = .DataRx;
    ch.local_window = 4;

    try std.testing.expectEqual(ch.local_id, table.findNextRunnable().?.local_id);

    ch.close_received = true;
    try std.testing.expect(table.findNextRunnable() == null);
}

test "OpenWrite channel state is runnable" {
    var table = ChannelTable{};
    const ch = table.allocChannel(10, 32768, 32768).?;
    ch.state = .OpenWrite;

    const runnable = table.findNextRunnable().?;
    try std.testing.expectEqual(ch.local_id, runnable.local_id);
}

test "consumeLocalWindow decrements local_window" {
    var ch = Channel.init(0, 1, 32768, 32768);
    const initial = ch.local_window;
    try ch.consumeLocalWindow(100);
    try std.testing.expectEqual(initial - 100, ch.local_window);
}

test "consumeLocalWindow rejects data above advertised window" {
    var ch = Channel.init(0, 1, 32768, 32768);
    ch.local_window = 50;
    try std.testing.expectError(error.ReceiveWindowExceeded, ch.consumeLocalWindow(200));
    try std.testing.expectEqual(@as(u32, 50), ch.local_window);
}

test "channel packet and receive window limits enforce below at and above" {
    var below = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 8,
        .packet_size = 4,
    });
    try below.consumeLocalWindow(3);
    try std.testing.expectEqual(@as(u32, 5), below.local_window);

    var exact = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 4,
        .packet_size = 4,
    });
    try exact.consumeLocalWindow(4);
    try std.testing.expectEqual(@as(u32, 0), exact.local_window);
    try std.testing.expect(exact.needsWindowAdjust());

    var one_byte = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 1,
        .packet_size = 1,
    });
    try one_byte.consumeLocalWindow(1);
    try std.testing.expect(one_byte.needsWindowAdjust());
    try std.testing.expectEqual(@as(u32, 1), one_byte.windowAdjustAmount());

    var packet_over = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 8,
        .packet_size = 4,
    });
    try std.testing.expectError(error.ChannelPacketTooLarge, packet_over.consumeLocalWindow(5));
    try std.testing.expectEqual(@as(u32, 8), packet_over.local_window);

    var window_over = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 4,
        .packet_size = 8,
    });
    try std.testing.expectError(error.ReceiveWindowExceeded, window_over.consumeLocalWindow(5));
    try std.testing.expectEqual(@as(u32, 4), window_over.local_window);
}

test "peer window adjustment rejects overflow without changing counter" {
    var ch = Channel.init(0, 1, 8, 8);
    try ch.adjustPeerWindow(2, 10);
    try std.testing.expectEqual(@as(u32, 10), ch.peer_window);
    try std.testing.expectError(error.WindowOverflow, ch.adjustPeerWindow(1, 10));
    try std.testing.expectEqual(@as(u32, 10), ch.peer_window);

    ch.peer_window = std.math.maxInt(u32);
    try std.testing.expectError(
        error.WindowOverflow,
        ch.adjustPeerWindow(1, std.math.maxInt(u32)),
    );
}

test "runtime channel count rejects above configured capacity" {
    var table = ChannelTable{ .limits = .{ .max_channels = 1 } };
    try std.testing.expect(table.allocChannel(1, 8, 8) != null);
    try std.testing.expectEqual(@as(u32, 1), table.activeCount());
    try std.testing.expect(table.allocChannel(2, 8, 8) == null);
}

test "needsWindowAdjust triggers below half advertised window" {
    var ch = Channel.init(0, 1, 32768, 32768);
    // At full window — no adjust needed
    try std.testing.expect(!ch.needsWindowAdjust());

    // Just above threshold — no adjust
    ch.local_window = Protocol.MaxChannelDataLen / 2;
    try std.testing.expect(!ch.needsWindowAdjust());

    // Below threshold — adjust needed
    ch.local_window = Protocol.MaxChannelDataLen / 2 - 1;
    try std.testing.expect(ch.needsWindowAdjust());
}

test "windowAdjustAmount replenishes advertised window" {
    var ch = Channel.init(0, 1, 32768, 32768);
    ch.local_window = 100;
    const adjust = ch.windowAdjustAmount();
    try std.testing.expectEqual(Protocol.MaxChannelDataLen - 100, adjust);

    // After applying the adjust, window should match the advertised window.
    ch.local_window = ch.local_window_target;
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, ch.local_window);
}

test "manual read credit rejects invalid excessive and overflowing counts" {
    var ch = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 8,
        .packet_size = 4,
    });
    ch.automatic_read_credit = false;
    try ch.consumeReceivedData(4);
    try std.testing.expectEqual(@as(u32, 4), ch.delivered_uncredited);
    try std.testing.expectError(error.InvalidChannelReadCredit, ch.queueReadCredit(0));
    try std.testing.expectError(error.ChannelReadCreditExceeded, ch.queueReadCredit(5));
    try std.testing.expectEqual(@as(u32, 4), ch.delivered_uncredited);
    try std.testing.expectEqual(@as(u32, 0), ch.pending_window_adjust);

    ch.local_window = ch.local_window_target;
    try std.testing.expectError(error.WindowOverflow, ch.queueReadCredit(1));
    try std.testing.expectEqual(@as(u32, 4), ch.delivered_uncredited);
    try std.testing.expectEqual(@as(u32, 0), ch.pending_window_adjust);
}

test "manual read credit supports partial consumption" {
    var ch = Channel.initKind(.Session, 0, 1, true, 100, 100, .{
        .initial_window = 8,
        .packet_size = 4,
    });
    ch.automatic_read_credit = false;
    try ch.consumeReceivedData(4);
    try ch.queueReadCredit(2);
    try std.testing.expectEqual(@as(u32, 2), ch.delivered_uncredited);
    try std.testing.expectEqual(@as(u32, 2), ch.pending_window_adjust);
    ch.applyWindowAdjust(ch.windowAdjustAmount());
    try std.testing.expectEqual(@as(u32, 6), ch.local_window);
    try std.testing.expectEqual(@as(u32, 0), ch.pending_window_adjust);
}

test "EofWrite is a runnable state" {
    var table = ChannelTable{};
    const ch = table.allocChannel(10, 32768, 32768).?;
    ch.state = .EofWrite;
    const runnable = table.findNextRunnable();
    try std.testing.expect(runnable != null);
    try std.testing.expectEqual(@as(u32, 0), runnable.?.local_id);
}

test "eof_sent and eof_received start false" {
    const ch = Channel.init(0, 1, 32768, 32768);
    try std.testing.expect(!ch.eof_sent);
    try std.testing.expect(!ch.eof_received);
}
