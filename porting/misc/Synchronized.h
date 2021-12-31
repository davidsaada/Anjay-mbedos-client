#ifndef BTTM_SYNCHRONIZED_H
#define BTTM_SYNCHRONIZED_H
#include <utility>
#include <mutex>

namespace misc {
/// @brief This class is a wrapper for type T that allows only synchronized access 
template<typename T, typename Mutex>
struct Synchronized : private T {
  // import all constructors from T
  using T::T;


  /// @brief Start synchronized block and call F in it
  /// @param f - piecie of code (function or function object) 
  ///        which will be called in the synchronized block
  ///        signature of F has to be void (T&)
  template<typename F>
  void sync_block(F&& f) {
    std::lock_guard<Mutex> lock{mx};
    std::forward<F>(f)(static_cast<T&>(*this));
  }

  /// @brief Start synchronized block and call F in it
  /// @param f - piecie of code (function or function object) 
  ///        which will be called in the synchronized block
  ///        signature of F has to be void (T const&)
  template<typename F>
  void sync_block(F&& f) const {
    std::lock_guard<Mutex> lock{mx};
    std::forward<F>(f)(static_cast<T const &>(*this));
  }


  /// @brief Allow nonsynchronized access to wrapped T objet
  /// @param f - piecie of code (function or function object) which will be called
  ///        signature of F has to be R (T&) where R can be void or any other type
  /// @return result of f       
  template<typename F>
  auto non_sync_block(F&& f) {
    return std::forward<F>(f)(static_cast<T&>(*this));
  }

  /// @brief Allow nonsynchronized access to wrapped T objet
  /// @param f - piecie of code (function or function object) which will be called
  ///        signature of F has to be R (T const&) where R can be void or any other type
  /// @return result of f       
  template<typename F>
  auto non_sync_block(F&& f) const {
    return std::forward<F>(f)(static_cast<T const &>(*this));
  }
 
private:
  mutable Mutex mx;
};

} // namespace misc

#endif // BTTM_SYNCHRONIZED_H
