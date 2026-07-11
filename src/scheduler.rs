use noq_proto::MultipathSchedulingPolicy as NoqSchedulingPolicy;

/// FlowWeave 对外使用的多路径调度策略。
///
/// 其他模块只认识这组名字，底层 NoQ 的类型集中在本文件转换，便于未来替换传输内核。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MultipathScheduler {
    /// 保留 NoQ 原本的低路径编号优先行为。
    #[default]
    NoqDefault,
    /// 用 ACK 确认交付率、在途字节和最小 RTT 预测完成时间，并允许有界等待。
    AckEcf,
}

impl MultipathScheduler {
    pub const CANDIDATES: [Self; 2] = [Self::NoqDefault, Self::AckEcf];

    pub fn description(self) -> &'static str {
        match self {
            Self::NoqDefault => "NoQ 默认（低编号优先）",
            Self::AckEcf => "ACK-ECF（确认交付完成时间优先）",
        }
    }

    pub(crate) fn to_noq(self) -> NoqSchedulingPolicy {
        match self {
            Self::NoqDefault => NoqSchedulingPolicy::Default,
            Self::AckEcf => NoqSchedulingPolicy::AckEcf,
        }
    }
}
