<?php
/**
 * AccessPolicy
 *
 * Copyright 2016 by Zaenal Muttaqin <zaenal(#)lokamaya.com>
 *
 * A general purpose for checking resource permission
 *
 * AccessPolicy is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) any
 * later version.
 *
 * AccessPolicy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * AccessPolicy; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * @package accesspolicy
 */
/**
 * AccessPolicy plugin
 * ------------------
 * A general purpose for checking resource permission
 * - apply nested resource group policy if needed
 * - redirect user to login page if required
 *
 * Requirement:
 * - Attach system event "OnWebPageInit" and "OnPageNotFound" onto this plugin
 * - Create new context/system setting: nested_resource_group. 
 *   Set it to "1" (or "true") to apply parents's Resource Groups policy for current request.
 * - Create new context/system setting: login_page (resource ID for login page)
 *   or set it on this plugin as scriptproperties (klik tab Properties > create property: login_page)
 * - Create new context/system setting: login_redirect. Set "forward" or "redirect" as its value.
 *   Or set it on this plugin as scriptproperties (klik tab Properties > create property: login_redirect)
 * 
**/
 
//don't process this plugin on manager context or any context we want
$excludeContext = array('mgr');
if (in_array($modx->context->get('key'), $excludeContext)) return;
 
global $checkResourceIdentifier;
 
//get login_page, unauthorized_page and error_page
$E401 = $modx->getOption('unauthorized_page', $scriptProperties, 0);
$E404 = $modx->getOption('error_page', $scriptProperties, 0);
$login_page = intval($modx->getOption('login_page', $scriptProperties, 0));
$login_redirect = $modx->getOption('login_redirect', $scriptProperties, 'redirect');
 
if (!isset($checkResourceIdentifier)) { 
    //invoked on "OnWebPageInit" when $modx->resourceIdentifier has been set properly
    //and save "default" resource ID on GLOBAL $checkResourceIdentifier
    $checkResourceIdentifier = $modx->resourceIdentifier;
    $nested_resource_group   = $modx->getOption('nested_resource_group', $scriptProperties, 0);
    $nested_resource_group   = $nested_resource_group == 'true' ? 1 : 0; 
     
    if (intval($nested_resource_group) == 1 && intval($checkResourceIdentifier) > 0) {
        $parentIds = array_diff($modx->getParentIds(intval($checkResourceIdentifier)), array(0));
     
        if (sizeof($parentIds) > 0) {
            $c = $modx->newQuery('modResource');
            $c->where(array(
                'id:IN' => array_values($parentIds),
                'deleted' => false,
                'published' => true
            ));
            $resources = $modx->getCollection('modResource',$c);
         
            if (sizeof($resources) < sizeof($parentIds)) {
                unset($resources);
     
                //don't process if "default" resource ID was error_page, unauthorized_page or login_page
                if ($checkResourceIdentifier == $E401 || $checkResourceIdentifier == $E404 || $checkResourceIdentifier == $login_page) return '';
                $checkResourceIdentifier = 0;
                 
                if (!$modx->user->hasSessionContext($modx->context->get('key')) && $login_page > 0) {
                    //if not logged in? redirect to login page
                    if ($login_redirect == 'forward') {
                        $modx->sendForward($login_page);
                    } else {
                        $modx->sendRedirect($modx->makeUrl($login_page, "", "", 'full'));
                    }                    
                } else {
                    //if logged in but have no privilege? send 401 unauthorized_page instead of 404 error_page
                    $modx->sendUnauthorizedPage();
                }                
            }
        }
    }
} elseif (isset($checkResourceIdentifier) && intval($checkResourceIdentifier) > 0 && intval($checkResourceIdentifier) == $checkResourceIdentifier) { 
    //invoked on "OnPageNotFound" after modRequest send 404 error
    //and check $checkResourceIdentifier > 0 (resource exist but no privilege)
 
    //don't process if "default" resource ID was error_page, unauthorized_page or login_page
    if ($checkResourceIdentifier == $E401 || $checkResourceIdentifier == $E404 || $checkResourceIdentifier == $login_page) return ''; 
     
    //set $checkResourceIdentifier to 0, to make sure the plugin doesn't make any looping process
    $checkResourceIdentifier = 0;
     
    if (!$modx->user->hasSessionContext($modx->context->get('key')) && $login_page > 0) {
        //if not logged in? redirect to login page
        if ($login_redirect == 'forward') {
            $modx->sendForward($login_page);
        } else {
            $modx->sendRedirect($modx->makeUrl($login_page, "", "", 'full'));
        }                    
    } else {
        //if logged in but have no privilege? send 401 unauthorized_page instead of 404 error_page
        $modx->sendUnauthorizedPage();
    }
}