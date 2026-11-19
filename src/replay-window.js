/**
 * 防重放滑动窗口（类似 IPsec 抗重放窗口）。
 *
 * 跟踪已接收的包号，拒绝三类异常：
 *  - 完全重复的包号（duplicate）
 *  - 低于窗口下界的陈旧包号（too_old，即包号回退/重放）
 * 窗口通过 WINDOW_UPDATE 事件或更大的包号自动向右滑动。
 */
export class ReplayWindow {
  constructor(size = 128) {
    if (!Number.isInteger(size) || size <= 0) {
      throw new RangeError('replay window size must be a positive integer');
    }
    this.size = size;
    this.highest = -1; // 目前见过的最大包号
    this.seen = new Set(); // 窗口内的包号
  }

  /** 窗口下界（含）：小于该值的包号视为陈旧。 */
  get floor() {
    return Math.max(0, this.highest - this.size + 1);
  }

  /**
   * 检查并记录一个包号。
   * @returns {{status: 'accepted'|'duplicate'|'too_old', highest: number}}
   */
  check(packetNumber) {
    if (!Number.isInteger(packetNumber) || packetNumber < 0) {
      throw new RangeError(`invalid packet number: ${packetNumber}`);
    }
    if (packetNumber > this.highest) {
      this.highest = packetNumber;
      this.seen.add(packetNumber);
      this.#evict();
      return { status: 'accepted', highest: this.highest };
    }
    if (packetNumber < this.floor) {
      return { status: 'too_old', highest: this.highest };
    }
    if (this.seen.has(packetNumber)) {
      return { status: 'duplicate', highest: this.highest };
    }
    this.seen.add(packetNumber);
    return { status: 'accepted', highest: this.highest };
  }

  /**
   * 处理 WINDOW_UPDATE：调整窗口大小，或显式推进窗口下界/最高点。
   */
  update({ size, highest } = {}) {
    if (size !== undefined) {
      if (!Number.isInteger(size) || size <= 0) {
        throw new RangeError('window size must be a positive integer');
      }
      this.size = size;
      this.#evict();
    }
    if (highest !== undefined && highest > this.highest) {
      this.highest = highest;
      this.#evict();
    }
  }

  #evict() {
    const floor = this.floor;
    for (const pn of this.seen) {
      if (pn < floor) this.seen.delete(pn);
    }
  }
}
