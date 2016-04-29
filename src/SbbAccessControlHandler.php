<?php

namespace Drupal\sbb;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Entity\EntityInterface;
use Drupal\user\UserAccessControlHandler;
use Drupal\Core\Session\AccountInterface;


class SbbAccessControlHandler extends UserAccessControlHandler {

    /**
   * {@inheritdoc}
   */
  protected function checkAccess(EntityInterface $entity, $operation, AccountInterface $account) {
    /** @var \Drupal\user\UserInterface $entity*/

    // We don't treat the user label as privileged information, so this check
    // has to be the first one in order to allow labels for all users to be
    // viewed, including the special anonymous user.
    if ($operation === 'view label') {
      return AccessResult::allowed();
    }

    // The anonymous user's profile can neither be viewed, updated nor deleted.
    if ($entity->isAnonymous()) {
      return AccessResult::forbidden();
    }

    // Administrators can view/update/delete all user profiles.
    if ($account->hasPermission('administer users')) {
      return AccessResult::allowed()->cachePerPermissions();
    }

    switch ($operation) {
      case 'view':
        // Only allow view access if the account is active.
        if ($account->hasPermission('access user profiles') /*&& $entity->isActive()*/) {
          return AccessResult::allowed()->cachePerPermissions()->addCacheableDependency($entity);
        }
        // Users can view own profiles at all times.
        elseif ($account->id() == $entity->id()) {
          return AccessResult::allowed()->cachePerUser();
        }
        break;

      case 'update':
        // Users can always edit their own account.
        return AccessResult::allowedIf($account->id() == $entity->id())->cachePerUser();

      case 'delete':
        // Users with 'cancel account' permission can cancel their own account.
        return AccessResult::allowedIf($account->id() == $entity->id() && $account->hasPermission('cancel account'))->cachePerPermissions()->cachePerUser();
    }

    // No opinion.
    return AccessResult::neutral();
  }
}