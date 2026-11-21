/**
 * @file tests/unit/platform/linux/test_clipboard_x11.cpp
 * @brief Tests for the X11 clipboard backend against the test X server (Xvfb).
 *
 * A small Xlib client in this file plays the "other application": it owns CLIPBOARD and serves
 * conversions (optionally via INCR), or requests conversions from the backend.
 */
#ifdef SUNSHINE_BUILD_X11_CLIPBOARD

  // test includes
  #include "../../../tests_common.h"

  // standard includes
  #include <array>
  #include <atomic>
  #include <chrono>
  #include <condition_variable>
  #include <cstdlib>
  #include <deque>
  #include <functional>
  #include <future>
  #include <map>
  #include <mutex>
  #include <optional>
  #include <string>
  #include <thread>
  #include <vector>

  // lib includes
  #include <fcntl.h>
  #include <poll.h>
  #include <unistd.h>
  #include <X11/Xatom.h>
  #include <X11/Xlib.h>

  // local includes
  #include "src/platform/linux/clipboard_linux.h"

using namespace std::literals;
using sds::clipboard::item_t;
using sds::clipboard::limits_t;

namespace {
  using bytes_t = std::vector<std::uint8_t>;

  constexpr Window no_window = None;  ///< None as a Window, for comparisons without sign warnings.

  /**
   * @brief Convert a string to bytes.
   */
  bytes_t to_bytes(std::string_view s) {
    return {s.begin(), s.end()};
  }

  /**
   * @brief Convert bytes to a string.
   */
  std::string to_string(const bytes_t &b) {
    return {b.begin(), b.end()};
  }

  /**
   * @brief A PNG signature and IHDR followed by `size` bytes of filler (only the header is inspected).
   */
  bytes_t fake_png(std::size_t size) {
    bytes_t png {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0};
    png.reserve(png.size() + size);
    for (std::size_t i = 0; i < size; ++i) {
      png.push_back(static_cast<std::uint8_t>(i * 131 + 7));
    }
    return png;
  }

  /**
   * @brief UTF-8 text of about `size` bytes with multi-byte characters.
   */
  std::string big_text(std::size_t size) {
    static const std::string unit =
      "Gr\xC3\xBC\xC3\x9F"
      "e \xE2\x9C\x93 \xE6\x97\xA5\xE6\x9C\xAC \xF0\x9F\x8E\x89\n";
    std::string text;
    text.reserve(size + unit.size());
    while (text.size() < size) {
      text += unit;
    }
    return text;
  }

  /**
   * @brief Another X client ("application") on its own connection and thread.
   */
  class x11_peer_t {
  public:
    /**
     * @brief What the peer offers while it owns CLIPBOARD.
     */
    struct offer_t {
      std::map<std::string, bytes_t> data;  ///< Target name -> bytes.
      std::size_t incr_chunk = 0;  ///< Serve data larger than this via INCR (0: never).
      bool stall = false;  ///< Never answer SelectionRequest.
      bool targets = true;  ///< Answer TARGETS.
    };

    x11_peer_t() = default;
    x11_peer_t(const x11_peer_t &) = delete;
    x11_peer_t &operator=(const x11_peer_t &) = delete;

    ~x11_peer_t() {
      close();
    }

    /**
     * @brief Connect to $DISPLAY and start the event thread.
     */
    bool open() {
      // Xvfb occasionally resets a new connection; retry like the backend does
      for (int attempt = 0; attempt < 10 && !dpy_; ++attempt) {
        if (attempt > 0) {
          std::this_thread::sleep_for(20ms * attempt);
        }
        dpy_ = XOpenDisplay(nullptr);
      }
      if (!dpy_) {
        return false;
      }
      win_ = XCreateSimpleWindow(dpy_, DefaultRootWindow(dpy_), 0, 0, 1, 1, 0, 0, 0);
      XSelectInput(dpy_, win_, PropertyChangeMask);
      clipboard_ = XInternAtom(dpy_, "CLIPBOARD", False);
      targets_ = XInternAtom(dpy_, "TARGETS", False);
      incr_ = XInternAtom(dpy_, "INCR", False);
      multiple_ = XInternAtom(dpy_, "MULTIPLE", False);
      atom_pair_ = XInternAtom(dpy_, "ATOM_PAIR", False);
      prop_ = XInternAtom(dpy_, "PEER_DATA", False);
      prop2_ = XInternAtom(dpy_, "PEER_DATA2", False);
      XSync(dpy_, False);
      if (pipe2(wake_.data(), O_CLOEXEC | O_NONBLOCK) != 0) {
        return false;
      }
      thread_ = std::thread(&x11_peer_t::run, this);
      return true;
    }

    /**
     * @brief Stop the thread and close the connection (destroying the peer's windows).
     */
    void close() {
      if (thread_.joinable()) {
        quit_ = true;
        wake();
        thread_.join();
      }
      if (dpy_) {
        XCloseDisplay(dpy_);
        dpy_ = nullptr;
      }
      for (auto &fd : wake_) {
        if (fd >= 0) {
          ::close(fd);
          fd = -1;
        }
      }
    }

    /**
     * @brief Take CLIPBOARD ownership with the given offer.
     */
    bool own(offer_t offer) {
      return call([this, offer = std::move(offer)]() {
        offered_.clear();
        for (const auto &[name, bytes] : offer.data) {
          offered_[XInternAtom(dpy_, name.c_str(), False)] = bytes;
        }
        offer_ = offer;
        XSetSelectionOwner(dpy_, clipboard_, win_, CurrentTime);
        owning_ = XGetSelectionOwner(dpy_, clipboard_) == win_;
        return owning_;
      });
    }

    /**
     * @brief Give up CLIPBOARD ownership.
     */
    void disown() {
      call([this]() {
        XSetSelectionOwner(dpy_, clipboard_, None, CurrentTime);
        owning_ = false;
        return 0;
      });
    }

    /**
     * @brief Current CLIPBOARD owner.
     */
    Window owner() {
      return call([this]() {
        return XGetSelectionOwner(dpy_, clipboard_);
      });
    }

    /**
     * @brief The peer's window.
     */
    Window window() const {
      return win_;
    }

    /**
     * @brief Convert CLIPBOARD to `target` (INCR supported) and return the bytes and type name.
     */
    std::optional<std::pair<bytes_t, std::string>> convert(const std::string &target, std::chrono::milliseconds timeout = 3s) {
      return call([this, target, timeout]() {
        return convert_on_thread(XInternAtom(dpy_, target.c_str(), False), prop_, timeout);
      });
    }

    /**
     * @brief Request MULTIPLE with (target, PEER_DATA) and (bogus, PEER_DATA2) and return both results.
     *
     * @return First pair's bytes and whether the second pair's property was set to None.
     */
    std::optional<std::pair<bytes_t, bool>> convert_multiple(const std::string &target) {
      return call([this, target]() -> std::optional<std::pair<bytes_t, bool>> {
        const Atom multiple_prop = XInternAtom(dpy_, "PEER_MULTIPLE", False);
        std::array<Atom, 4> pairs {XInternAtom(dpy_, target.c_str(), False), prop_, XInternAtom(dpy_, "image/x-bogus", False), prop2_};
        XChangeProperty(dpy_, win_, multiple_prop, atom_pair_, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(pairs.data()), 4);
        XConvertSelection(dpy_, clipboard_, multiple_, multiple_prop, win_, CurrentTime);
        XFlush(dpy_);
        XEvent event;
        if (!wait_event(event, 3s, [&](const XEvent &e) {
              return e.type == SelectionNotify && e.xselection.requestor == win_;
            }) ||
            event.xselection.property == None) {
          return std::nullopt;
        }
        Atom type;
        int format;
        unsigned long items;
        unsigned long after;
        unsigned char *data = nullptr;
        XGetWindowProperty(dpy_, win_, multiple_prop, 0, 16, True, AnyPropertyType, &type, &format, &items, &after, &data);
        if (!data || items != 4) {
          return std::nullopt;
        }
        const auto *result = reinterpret_cast<const unsigned long *>(data);
        const bool second_refused = result[3] == None;
        XFree(data);
        auto first = read_property(prop_);
        if (!first) {
          return std::nullopt;
        }
        return std::pair {first->first, second_refused};
      });
    }

    /**
     * @brief Start converting `target`; stop after the owner announced INCR, without deleting the property.
     *
     * @return True when the owner answered with INCR.
     */
    bool convert_and_stall(const std::string &target) {
      return call([this, target]() {
        XDeleteProperty(dpy_, win_, prop_);
        XConvertSelection(dpy_, clipboard_, XInternAtom(dpy_, target.c_str(), False), prop_, win_, CurrentTime);
        XFlush(dpy_);
        XEvent event;
        if (!wait_event(event, 3s, [&](const XEvent &e) {
              return e.type == SelectionNotify && e.xselection.requestor == win_;
            }) ||
            event.xselection.property == None) {
          return false;
        }
        Atom type;
        int format;
        unsigned long items;
        unsigned long after;
        unsigned char *data = nullptr;
        XGetWindowProperty(dpy_, win_, prop_, 0, 1, False, AnyPropertyType, &type, &format, &items, &after, &data);
        if (data) {
          XFree(data);
        }
        purge_property_events(prop_);
        return type == incr_;
      });
    }

    /**
     * @brief Delete the stalled INCR property and report whether a chunk arrives within `wait`.
     */
    bool resume_stalled_gets_chunk(std::chrono::milliseconds wait) {
      return call([this, wait]() {
        XDeleteProperty(dpy_, win_, prop_);
        XFlush(dpy_);
        XEvent event;
        return wait_event(event, wait, [&](const XEvent &e) {
          return e.type == PropertyNotify && e.xproperty.window == win_ && e.xproperty.atom == prop_ && e.xproperty.state == PropertyNewValue;
        });
      });
    }

    /**
     * @brief Delete the stalled INCR property (asking for the next chunk) without waiting.
     */
    void resume_stalled_async() {
      call([this]() {
        XDeleteProperty(dpy_, win_, prop_);
        XFlush(dpy_);
        return 0;
      });
    }

    /**
     * @brief Number of requests the peer has seen while owning.
     */
    int requests_seen() const {
      return requests_.load();
    }

  private:
    /**
     * @brief An INCR transfer from the peer to a requestor.
     */
    struct transfer_t {
      Window requestor;  ///< Receiving window.
      Atom property;  ///< Receiving property.
      Atom type;  ///< Data type.
      bytes_t data;  ///< Payload.
      std::size_t offset = 0;  ///< Bytes sent.
    };

    /**
     * @brief Run `f` on the peer thread and return its result.
     */
    template<typename F>
    auto call(F f) -> decltype(f()) {
      std::packaged_task<decltype(f())()> task(std::move(f));
      auto future = task.get_future();
      {
        std::lock_guard lock(mutex_);
        tasks_.emplace_back([&task]() {
          task();
        });
      }
      wake();
      return future.get();
    }

    /**
     * @brief Interrupt the peer thread's poll().
     */
    void wake() {
      const char byte = 1;
      [[maybe_unused]] auto n = ::write(wake_[1], &byte, 1);
    }

    /**
     * @brief Peer event thread.
     */
    void run() {
      const int xfd = ConnectionNumber(dpy_);
      while (!quit_) {
        std::deque<std::function<void()>> tasks;
        {
          std::lock_guard lock(mutex_);
          tasks.swap(tasks_);
        }
        for (auto &task : tasks) {
          task();
        }
        while (XPending(dpy_) > 0) {
          XEvent event;
          XNextEvent(dpy_, &event);
          handle(event);
        }
        if (XPending(dpy_) > 0) {
          continue;  // events already read into Xlib's queue are invisible to poll()
        }
        std::array<pollfd, 2> fds {{{xfd, POLLIN, 0}, {wake_[0], POLLIN, 0}}};
        poll(fds.data(), fds.size(), 100);
        std::array<char, 64> sink {};
        while (::read(wake_[0], sink.data(), sink.size()) > 0) {
        }
      }
    }

    /**
     * @brief Handle one event on the peer thread.
     */
    void handle(const XEvent &event) {
      if (event.type == SelectionRequest) {
        serve(event.xselectionrequest);
      } else if (event.type == SelectionClear) {
        owning_ = false;
      } else if (event.type == PropertyNotify && event.xproperty.window != win_ && event.xproperty.state == PropertyDelete) {
        continue_transfer(event.xproperty);
      }
    }

    /**
     * @brief Answer a SelectionRequest from the backend.
     */
    void serve(const XSelectionRequestEvent &request) {
      ++requests_;
      if (offer_.stall) {
        return;
      }
      XSelectionEvent reply {};
      reply.type = SelectionNotify;
      reply.display = dpy_;
      reply.requestor = request.requestor;
      reply.selection = request.selection;
      reply.target = request.target;
      reply.time = request.time;
      reply.property = None;
      if (owning_) {
        if (request.target == targets_ && offer_.targets) {
          std::vector<Atom> list {targets_};
          for (const auto &[atom, bytes] : offered_) {
            list.push_back(atom);
          }
          XChangeProperty(dpy_, request.requestor, request.property, XA_ATOM, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(list.data()), static_cast<int>(list.size()));
          reply.property = request.property;
        } else if (const auto it = offered_.find(request.target); it != offered_.end()) {
          const auto &bytes = it->second;
          if (offer_.incr_chunk > 0 && bytes.size() > offer_.incr_chunk) {
            XSelectInput(dpy_, request.requestor, PropertyChangeMask);
            const long size = static_cast<long>(bytes.size());
            XChangeProperty(dpy_, request.requestor, request.property, incr_, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(&size), 1);
            transfers_.push_back({request.requestor, request.property, request.target, bytes, 0});
          } else {
            XChangeProperty(dpy_, request.requestor, request.property, request.target, 8, PropModeReplace, bytes.data(), static_cast<int>(bytes.size()));
          }
          reply.property = request.property;
        }
      }
      XSendEvent(dpy_, request.requestor, False, NoEventMask, reinterpret_cast<XEvent *>(&reply));
      XFlush(dpy_);
    }

    /**
     * @brief Send the next INCR chunk to a requestor that deleted the property.
     */
    void continue_transfer(const XPropertyEvent &event) {
      for (auto it = transfers_.begin(); it != transfers_.end(); ++it) {
        if (it->requestor != event.window || it->property != event.atom) {
          continue;
        }
        const std::size_t n = std::min(offer_.incr_chunk, it->data.size() - it->offset);
        XChangeProperty(dpy_, it->requestor, it->property, it->type, 8, PropModeReplace, it->data.data() + it->offset, static_cast<int>(n));
        it->offset += n;
        if (n == 0) {
          transfers_.erase(it);
        }
        XFlush(dpy_);
        return;
      }
    }

    /**
     * @brief Wait on the peer thread for an event matching `match` (other events stay queued).
     */
    bool wait_event(XEvent &out, std::chrono::milliseconds timeout, const std::function<bool(const XEvent &)> &match) {
      const auto deadline = std::chrono::steady_clock::now() + timeout;
      auto predicate = [](Display *, XEvent *event, XPointer arg) -> Bool {
        return (*reinterpret_cast<const std::function<bool(const XEvent &)> *>(arg))(*event) ? True : False;
      };
      while (true) {
        if (XCheckIfEvent(dpy_, &out, predicate, reinterpret_cast<XPointer>(const_cast<std::function<bool(const XEvent &)> *>(&match)))) {
          return true;
        }
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
          return false;
        }
        pollfd pfd {ConnectionNumber(dpy_), POLLIN, 0};
        poll(&pfd, 1, static_cast<int>(std::min<long long>(remaining, 50)));
      }
    }

    /**
     * @brief Drop queued PropertyNotify events for `property` on the peer window.
     */
    void purge_property_events(Atom property) {
      XEvent event;
      auto predicate = [](Display *, XEvent *e, XPointer arg) -> Bool {
        return e->type == PropertyNotify && e->xproperty.atom == *reinterpret_cast<Atom *>(arg);
      };
      while (XCheckIfEvent(dpy_, &event, predicate, reinterpret_cast<XPointer>(&property))) {
      }
    }

    /**
     * @brief Read (and delete) a complete property from the peer window, following INCR.
     */
    std::optional<std::pair<bytes_t, std::string>> read_property(Atom property, std::chrono::milliseconds timeout = 3s) {
      Atom type;
      int format;
      unsigned long items;
      unsigned long after;
      unsigned char *data = nullptr;
      if (XGetWindowProperty(dpy_, win_, property, 0, 0x1FFFFFFF, False, AnyPropertyType, &type, &format, &items, &after, &data) != Success || type == None) {
        return std::nullopt;
      }
      bytes_t bytes;
      if (type != incr_) {
        const std::size_t unit = format == 8 ? 1 : (format == 16 ? sizeof(short) : sizeof(long));
        bytes.assign(data, data + items * unit);
        XFree(data);
        XDeleteProperty(dpy_, win_, property);
        char *name = XGetAtomName(dpy_, type);
        std::string type_name = name ? name : "";
        XFree(name);
        return std::pair {bytes, type_name};
      }
      XFree(data);
      purge_property_events(property);
      XDeleteProperty(dpy_, win_, property);
      XFlush(dpy_);
      Atom chunk_type = None;
      while (true) {
        XEvent event;
        if (!wait_event(event, timeout, [&](const XEvent &e) {
              return e.type == PropertyNotify && e.xproperty.window == win_ && e.xproperty.atom == property && e.xproperty.state == PropertyNewValue;
            })) {
          return std::nullopt;
        }
        unsigned char *chunk = nullptr;
        XGetWindowProperty(dpy_, win_, property, 0, 0x1FFFFFFF, True, AnyPropertyType, &chunk_type, &format, &items, &after, &chunk);
        if (chunk) {
          bytes.insert(bytes.end(), chunk, chunk + items);
          XFree(chunk);
        }
        XFlush(dpy_);
        if (items == 0) {
          break;
        }
      }
      char *name = chunk_type == None ? nullptr : XGetAtomName(dpy_, chunk_type);
      std::string type_name = name ? name : "";
      if (name) {
        XFree(name);
      }
      return std::pair {bytes, type_name};
    }

    /**
     * @brief Convert CLIPBOARD to `target` on the peer thread.
     */
    std::optional<std::pair<bytes_t, std::string>> convert_on_thread(Atom target, Atom property, std::chrono::milliseconds timeout) {
      XDeleteProperty(dpy_, win_, property);
      XConvertSelection(dpy_, clipboard_, target, property, win_, CurrentTime);
      XFlush(dpy_);
      XEvent event;
      if (!wait_event(event, timeout, [&](const XEvent &e) {
            return e.type == SelectionNotify && e.xselection.requestor == win_ && e.xselection.target == target;
          }) ||
          event.xselection.property == None) {
        return std::nullopt;
      }
      return read_property(property, timeout);
    }

    Display *dpy_ = nullptr;
    Window win_ = None;
    Atom clipboard_ = None;
    Atom targets_ = None;
    Atom incr_ = None;
    Atom multiple_ = None;
    Atom atom_pair_ = None;
    Atom prop_ = None;
    Atom prop2_ = None;
    std::array<int, 2> wake_ {-1, -1};
    std::thread thread_;
    std::atomic<bool> quit_ {false};
    std::mutex mutex_;
    std::deque<std::function<void()>> tasks_;
    offer_t offer_;
    std::map<Atom, bytes_t> offered_;
    bool owning_ = false;
    std::vector<transfer_t> transfers_;
    std::atomic<int> requests_ {0};
  };

  constexpr limits_t big_limits {4 * 1024 * 1024, 4 * 1024 * 1024};

  /**
   * @brief Runs each test with a started backend and a peer application on the test display.
   */
  class X11ClipboardTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      if (HasFatalFailure() || IsSkipped()) {
        return;
      }
      const char *display = std::getenv("DISPLAY");
      if (!display || !*display) {
        GTEST_SKIP() << "DISPLAY is not set";
      }
      if (!peer_.open()) {
        GTEST_SKIP() << "Cannot open the X display";
      }
      backend_ = sds::clipboard::x11::make_backend({.transfer_timeout = 400ms, .incr_chunk = 0});
      ASSERT_EQ(backend_->start([this]() {
        std::lock_guard lock(mutex_);
        ++changes_;
        cv_.notify_all();
      }),
                0);
      EXPECT_EQ(backend_->name(), "x11");
    }

    void TearDown() override {
      if (backend_) {
        backend_->stop();
      }
      peer_.close();
      BaseTest::TearDown();
    }

    /**
     * @brief Wait until at least `count` change notifications arrived.
     */
    bool wait_changes(int count, std::chrono::milliseconds timeout = 3s) {
      std::unique_lock lock(mutex_);
      return cv_.wait_for(lock, timeout, [&]() {
        return changes_ >= count;
      });
    }

    /**
     * @brief Number of change notifications so far.
     */
    int changes() {
      std::lock_guard lock(mutex_);
      return changes_;
    }

    x11_peer_t peer_;
    std::unique_ptr<sds::clipboard::backend_t> backend_;
    std::mutex mutex_;
    std::condition_variable cv_;
    int changes_ = 0;
  };
}  // namespace

TEST_F(X11ClipboardTest, ReadsUtf8TextFromOtherClient) {
  const std::string text = "h\xC3\xA9llo w\xC3\xB6rld \xE2\x80\x94 \xE2\x9C\x93 \xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E \xF0\x9F\x8E\x89";
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes(text)}, {"STRING", to_bytes("fallback")}}}));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, text);
  EXPECT_FALSE(item->png);
}

TEST_F(X11ClipboardTest, ReadPrefersUtf8StringOverMimeText) {
  ASSERT_TRUE(peer_.own({.data = {{"text/plain;charset=utf-8", to_bytes("mime")}, {"UTF8_STRING", to_bytes("utf8")}}}));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "utf8");
}

TEST_F(X11ClipboardTest, ReadsMimeTextAndStripsTrailingNul) {
  ASSERT_TRUE(peer_.own({.data = {{"text/plain;charset=utf-8", bytes_t {'a', 'b', 0}}}}));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "ab");
}

TEST_F(X11ClipboardTest, ReadsLatin1StringAsUtf8) {
  ASSERT_TRUE(peer_.own({.data = {{"STRING", to_bytes("caf\xE9")}}}));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "caf\xC3\xA9");
}

TEST_F(X11ClipboardTest, ReadsWithoutTargetsSupport) {
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("no targets")}}, .targets = false}));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "no targets");
}

TEST_F(X11ClipboardTest, ReadsPngAndText) {
  const auto png = fake_png(1000);
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("caption")}, {"image/png", png}}}));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "caption");
  EXPECT_EQ(item->png, png);
}

TEST_F(X11ClipboardTest, IgnoresImageWithoutPngSignature) {
  ASSERT_TRUE(peer_.own({.data = {{"image/png", to_bytes("GIF89a not a png")}}}));
  EXPECT_FALSE(backend_->read(big_limits, 3s));
}

TEST_F(X11ClipboardTest, ReadsLargeDataViaIncr) {
  const auto text = big_text(1536 * 1024);
  const auto png = fake_png(1536 * 1024);
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes(text)}, {"image/png", png}}, .incr_chunk = 64 * 1024}));
  const auto item = backend_->read(big_limits, 10s);
  ASSERT_TRUE(item);
  ASSERT_TRUE(item->text);
  EXPECT_EQ(item->text->size(), text.size());
  EXPECT_EQ(*item->text, text);
  EXPECT_EQ(item->png, png);
}

TEST_F(X11ClipboardTest, DropsOversizedRepresentations) {
  const auto png = fake_png(100);
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes(std::string(2000, 'x'))}, {"image/png", png}}}));
  auto item = backend_->read({1000, 1000}, 3s);
  ASSERT_TRUE(item);
  EXPECT_FALSE(item->text);
  EXPECT_EQ(item->png, png);

  item = backend_->read({1000, 50}, 3s);
  EXPECT_FALSE(item);  // both representations too large
}

TEST_F(X11ClipboardTest, DropsOversizedIncrTransferAndRecovers) {
  const auto text = big_text(1536 * 1024);
  const auto png = fake_png(200);
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes(text)}, {"image/png", png}}, .incr_chunk = 64 * 1024}));
  auto item = backend_->read({1024 * 1024, 1024 * 1024}, 10s);
  ASSERT_TRUE(item);
  EXPECT_FALSE(item->text);
  EXPECT_EQ(item->png, png);

  // The aborted transfer is drained; later reads still work
  item = backend_->read(big_limits, 10s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, text);
}

TEST_F(X11ClipboardTest, ReadTimesOutWhenOwnerDoesNotAnswer) {
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("never sent")}}, .stall = true}));
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(backend_->read(big_limits, 300ms));
  const auto elapsed = std::chrono::steady_clock::now() - start;
  EXPECT_LT(elapsed, 600ms);
  EXPECT_GE(peer_.requests_seen(), 1);
}

TEST_F(X11ClipboardTest, ReadReturnsNothingWithoutOwner) {
  peer_.disown();
  EXPECT_FALSE(backend_->read(big_limits, 1s));
}

TEST_F(X11ClipboardTest, ServesTextTargetsToOtherClient) {
  const std::string text = "caf\xC3\xA9 \xE2\x9C\x93 \xF0\x9F\x8E\x89";
  ASSERT_EQ(backend_->write({.text = text, .png = std::nullopt}), 0);
  EXPECT_NE(peer_.owner(), no_window);
  EXPECT_NE(peer_.owner(), peer_.window());

  auto result = peer_.convert("UTF8_STRING");
  ASSERT_TRUE(result);
  EXPECT_EQ(to_string(result->first), text);
  EXPECT_EQ(result->second, "UTF8_STRING");

  result = peer_.convert("text/plain;charset=utf-8");
  ASSERT_TRUE(result);
  EXPECT_EQ(to_string(result->first), text);

  result = peer_.convert("STRING");
  ASSERT_TRUE(result);
  EXPECT_EQ(to_string(result->first), "caf\xE9 ? ?");
  EXPECT_EQ(result->second, "STRING");

  EXPECT_FALSE(peer_.convert("image/png"));  // not offered
}

TEST_F(X11ClipboardTest, ServesTargetsTimestampAndMultiple) {
  ASSERT_EQ(backend_->write({.text = "t", .png = fake_png(10)}), 0);
  const auto targets = peer_.convert("TARGETS");
  ASSERT_TRUE(targets);
  EXPECT_EQ(targets->second, "ATOM");
  const auto count = targets->first.size() / sizeof(long);
  EXPECT_EQ(count, 7u);  // TARGETS TIMESTAMP MULTIPLE UTF8_STRING text/plain;charset=utf-8 STRING image/png

  const auto timestamp = peer_.convert("TIMESTAMP");
  ASSERT_TRUE(timestamp);
  EXPECT_EQ(timestamp->second, "INTEGER");

  const auto multiple = peer_.convert_multiple("UTF8_STRING");
  ASSERT_TRUE(multiple);
  EXPECT_EQ(to_string(multiple->first), "t");
  EXPECT_TRUE(multiple->second);
}

TEST_F(X11ClipboardTest, ServesPng) {
  const auto png = fake_png(5000);
  ASSERT_EQ(backend_->write({.text = std::nullopt, .png = png}), 0);
  const auto result = peer_.convert("image/png");
  ASSERT_TRUE(result);
  EXPECT_EQ(result->first, png);
  EXPECT_EQ(result->second, "image/png");
  EXPECT_FALSE(peer_.convert("UTF8_STRING"));
}

TEST_F(X11ClipboardTest, ServesLargeDataViaIncr) {
  const auto text = big_text(1536 * 1024);
  const auto png = fake_png(1536 * 1024);
  ASSERT_EQ(backend_->write({.text = text, .png = png}), 0);
  auto result = peer_.convert("UTF8_STRING", 10s);
  ASSERT_TRUE(result);
  EXPECT_EQ(result->first.size(), text.size());
  EXPECT_EQ(to_string(result->first), text);
  result = peer_.convert("image/png", 10s);
  ASSERT_TRUE(result);
  EXPECT_EQ(result->first, png);
}

TEST_F(X11ClipboardTest, ReadOfOwnContentNeedsNoRoundTrip) {
  ASSERT_EQ(backend_->write({.text = "mine", .png = fake_png(10)}), 0);
  auto item = backend_->read(big_limits, 1s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "mine");
  item = backend_->read({100, 5}, 1s);
  ASSERT_TRUE(item);
  EXPECT_FALSE(item->png);
}

TEST_F(X11ClipboardTest, NotifiesForOtherClientsOnly) {
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("a")}}}));
  ASSERT_TRUE(wait_changes(1));

  const int before = changes();
  ASSERT_EQ(backend_->write({.text = "ours", .png = std::nullopt}), 0);
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(changes(), before);

  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("b")}}}));
  EXPECT_TRUE(wait_changes(before + 1));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "b");  // ownership moved to the peer
}

TEST_F(X11ClipboardTest, NotifiesWhenOwnerGoesAway) {
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("a")}}}));
  ASSERT_TRUE(wait_changes(1));
  const int before = changes();
  peer_.close();  // owner window destroyed with its connection
  EXPECT_TRUE(wait_changes(before + 1));
}

TEST_F(X11ClipboardTest, StopReleasesOwnershipAndIsIdempotent) {
  ASSERT_EQ(backend_->write({.text = "bye", .png = std::nullopt}), 0);
  const Window owner = peer_.owner();
  EXPECT_NE(owner, no_window);
  backend_->stop();
  EXPECT_EQ(peer_.owner(), no_window);
  backend_->stop();
  EXPECT_FALSE(backend_->read(big_limits, 100ms));
  EXPECT_EQ(backend_->write({.text = "x", .png = std::nullopt}), -1);
}

TEST_F(X11ClipboardTest, RestartsAfterStop) {
  backend_->stop();
  ASSERT_EQ(backend_->start([]() {
  }),
            0);
  ASSERT_EQ(backend_->write({.text = "again", .png = std::nullopt}), 0);
  const auto result = peer_.convert("UTF8_STRING");
  ASSERT_TRUE(result);
  EXPECT_EQ(to_string(result->first), "again");
}

TEST_F(X11ClipboardTest, EmptyWriteReleasesOwnership) {
  ASSERT_EQ(backend_->write({.text = "x", .png = std::nullopt}), 0);
  ASSERT_EQ(backend_->write({}), 0);
  EXPECT_EQ(peer_.owner(), no_window);
}

TEST_F(X11ClipboardTest, DropsStalledIncrRequestor) {
  ASSERT_EQ(backend_->write({.text = big_text(1024 * 1024), .png = std::nullopt}), 0);
  ASSERT_TRUE(peer_.convert_and_stall("UTF8_STRING"));
  // Longer than the backend's 400 ms transfer timeout
  std::this_thread::sleep_for(900ms);
  EXPECT_FALSE(peer_.resume_stalled_gets_chunk(500ms));

  // The backend still serves new requests
  const auto result = peer_.convert("TARGETS");
  EXPECT_TRUE(result);
}

TEST_F(X11ClipboardTest, SurvivesRequestorThatDisappears) {
  const auto text = big_text(1024 * 1024);
  ASSERT_EQ(backend_->write({.text = text, .png = std::nullopt}), 0);
  {
    x11_peer_t requestor;
    ASSERT_TRUE(requestor.open());
    ASSERT_TRUE(requestor.convert_and_stall("UTF8_STRING"));
    requestor.resume_stalled_async();  // asks for a chunk ...
    requestor.close();  // ... and vanishes; the backend's next write hits a dead window
  }
  std::this_thread::sleep_for(200ms);
  const auto result = peer_.convert("UTF8_STRING", 10s);
  ASSERT_TRUE(result);
  EXPECT_EQ(to_string(result->first), text);
}

TEST_F(X11ClipboardTest, ConcurrentReadsAreSerialized) {
  ASSERT_TRUE(peer_.own({.data = {{"UTF8_STRING", to_bytes("shared")}}}));
  std::vector<std::future<std::optional<item_t>>> reads;
  for (int i = 0; i < 4; ++i) {
    reads.push_back(std::async(std::launch::async, [this]() {
      return backend_->read(big_limits, 5s);
    }));
  }
  for (auto &read : reads) {
    const auto item = read.get();
    ASSERT_TRUE(item);
    EXPECT_EQ(item->text, "shared");
  }
}

TEST(X11ClipboardStartTest, FailsWithoutDisplay) {
  const char *previous = std::getenv("DISPLAY");
  const std::string saved = previous ? previous : "";
  logging::log_flush();
  setenv("DISPLAY", ":4242", 1);
  auto backend = sds::clipboard::x11::make_backend();
  EXPECT_LT(backend->start([]() {
  }),
            0);
  EXPECT_FALSE(backend->read(big_limits, 100ms));
  EXPECT_EQ(backend->write({.text = "x", .png = std::nullopt}), -1);
  backend->stop();
  logging::log_flush();
  if (previous) {
    setenv("DISPLAY", saved.c_str(), 1);
  } else {
    unsetenv("DISPLAY");
  }
}

#endif
