use noq_proto::MultipathSchedulingPolicy as NoqSchedulingPolicy;

/// FlowWeave 对外使用的多路径调度策略。
///
/// 其他模块只认识这组名字，底层 NoQ 的类型集中在本文件转换，便于未来替换传输内核。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MultipathScheduler {
    /// 保留 NoQ 原本的低路径编号优先行为。
    #[default]
    NoqDefault,
    /// 每次成功发送一批数据后换到下一条可用路径。
    RoundRobin,
    /// 优先选择当前往返延迟最低的路径。
    MinRtt,
    /// 同时考虑延迟、拥塞窗口和在途数据，选择预计最早送达的路径。
    EarliestDelivery,
}

impl MultipathScheduler {
    pub const CANDIDATES: [Self; 4] = [
        Self::NoqDefault,
        Self::RoundRobin,
        Self::MinRtt,
        Self::EarliestDelivery,
    ];

    pub fn description(self) -> &'static str {
        match self {
            Self::NoqDefault => "NoQ 默认（低编号优先）",
            Self::RoundRobin => "轮询",
            Self::MinRtt => "最低 RTT",
            Self::EarliestDelivery => "预计最早送达",
        }
    }

    pub(crate) fn to_noq(self) -> NoqSchedulingPolicy {
        match self {
            Self::NoqDefault => NoqSchedulingPolicy::Default,
            Self::RoundRobin => NoqSchedulingPolicy::RoundRobin,
            Self::MinRtt => NoqSchedulingPolicy::MinRtt,
            Self::EarliestDelivery => NoqSchedulingPolicy::EarliestDelivery,
        }
    }
}
