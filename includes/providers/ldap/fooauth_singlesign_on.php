<?php

if (!class_exists('FooAuth_Single_Signon')) {
  class FooAuth_Single_Signon {

    function __construct() {

			// For debugging
      // add_action('after_setup_theme', array($this, 'print_user_data'));

      add_action( 'after_setup_theme', array($this, 'auto_login'));
      // add_action('wp_login', array($this, 'user_authorization_check'), 10, 2);
      add_action( 'load-post.php', array($this, 'auth_metabox_setup'));
      add_action( 'load-post-new.php', array($this, 'auth_metabox_setup'));

			// Add columns on user admin page, and populate with AD data
			add_filter( 'manage_users_columns', array($this, 'add_user_columns'));
			add_filter( 'manage_users_custom_column', array($this, 'add_user_column_data'), 10, 3 );

      add_filter( 'manage_pages_columns', array($this, 'add_page_columns'), 10, 2 );
      add_filter( 'manage_pages_custom_column', array($this, 'add_page_columns_data'), 10, 2 );
      add_action( 'bulk_edit_custom_box', array($this, 'add_to_bulk_quick_edit_custom_box'), 10, 2 );
      add_action( 'quick_edit_custom_box', array($this, 'add_to_bulk_quick_edit_custom_box'), 10, 2 );
      add_action( 'admin_print_scripts-edit.php', array($this, 'enqueue_edit_scripts') );
      add_action( 'save_post', array($this, 'save_post'), 10, 2 );
      add_action( 'wp_ajax_save_bulk_edit', array($this, 'save_bulk_edit') );      

      if (!is_admin()) {
        add_action('pre_get_posts', array($this, 'filter_allowed_posts'));
      }
      if (!is_admin()) {
        add_action('wp', array($this, 'check_user_authorization'));
      }
    }

		function print_user_data() {
			if(!is_admin()) {
				$user_info = $this->get_current_user_info();
				$username = $this->get_actual_username($user_info);
				$user_id = username_exists($username);

				$user = get_userdata($user_id);
				
				echo '<pre>';
				print_r( $this->get_details_from_ldap( $username ) );
				echo '</pre>';
			}
		}

    // Auto Login a user
    // =================================================================
    function auto_login() {
      if ($this->is_sso_enabled()  && !is_admin()) {
        $user_info = $this->get_current_user_info();
        
        // We cant get Windows Auth details, stop all processing
        if ($user_info === false) return false;

        $username = $this->get_actual_username($user_info);        

        //check if the user has access to log in to the site
        // $this->user_authorization_check($username, null);

        if (!$this->can_user_be_created()) return true;

        // Check if Username exists already in Wordpress
        $user_id = username_exists($username);

        // If User is not on the login page, and is NOT logged in
        if (!$this->is_on_login_page() && !is_user_logged_in()) { 

          if ($user_id && !$this->is_admin_user($user_id) ) {
            // User exists, update their details
            $this->update_user_details($username, $user_id); 
          } else {
            // User doesnt exist, create a new user for them
            $user_id = $this->register_new_user($username);
          }

          if (isset($user_id) && !is_wp_error($user_id)) {
            wp_set_current_user($user_id, $username);
            wp_set_auth_cookie($user_id);
            do_action('wp_login', $username);
          }
        }
        // If User is not on the login page, and is logged in, and not in the dashboard
        else if (!$this->is_on_login_page() && is_user_logged_in() && !$this->is_admin_user($user_id) ) {
          // echo 'update user details!!';
          $this->update_user_details($username, $user_id);
        }

      }
    }

    private function get_details_from_ldap($username) {
      $options = FooAuth::get_instance()->options();

      $fqdn = $options->get('ldap_fqdn');
      $ou = $options->get('ldap_organizational_unit');
      $ldap_username = $options->get('ldap_username');
      $ldap_password = $options->get('ldap_password');
      $display_name_option = $options->get('display_name', 'displayName');

      $ldapCred = $ldap_username . '@' . $fqdn;
      try {
        $connection = ldap_connect('ldap://' . $fqdn, 389);
        //Set some variables
        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($connection, LDAP_OPT_NETWORK_TIMEOUT, 10);

        try {
          //Bind to the ldap directory
          $ldapbind = ldap_bind($connection, $ldapCred, $ldap_password);

          if($ldapbind) {
            //Search the directory
            $result = ldap_search($connection, $ou, '(samaccountname=' . $username . ')');
            //Create result set
            $entries = ldap_get_entries($connection, $result);

            $email = (empty($entries[0]["mail"][0]) ? $username . '@' . $fqdn : $entries[0]["mail"][0]);
            $firstname = $entries[0]["givenname"][0];
            $surname = $entries[0]["sn"][0];
            $display_name = $entries[0]["$display_name_option"][0];
            $department = $entries[0]["department"][0];
            $location = $entries[0]["company"][0];
            $manager_name = explode(',', $entries[0]["manager"][0]);
            $manager = str_replace('CN=', '', $manager_name);

            return array(
              'email' => $email,
              'name' => $firstname,
              'surname' => $surname,
              'display_name' => $display_name,
              'department' => $department,
              'location' => $location,
              'manager' => $manager[0]
            );
          } 

        } catch (Exception $e) {
          return new WP_Error('666', 'Caught exception binding to LDAP Directory: ', $e->getMessage());
        }
      } catch (Exception $e) {
        return new WP_Error('666', 'Caught exception connecting to domain: ', $e->getMessage());
      }
    }



    private function get_current_page_url() {
      $page_URL = 'http';
      if ($_SERVER["HTTPS"] == "on") {
        $page_URL .= "s";
      }
      $page_URL .= "://";
      if ($_SERVER["SERVER_PORT"] != "80") {
        $page_URL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
      } else {
        $page_URL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
      }
      return $page_URL;
    }

    private function can_user_be_created() {
      //check if the user has been redirected to the redirect page and aren't logged in
      if ($this->is_on_redirect_page() && !is_user_logged_in()) {
        return false;
      }
      return true;
    }

    private function is_on_login_page() {
      return 'wp-login.php' === $GLOBALS['pagenow'];
    }

    private function is_on_redirect_page() {
      $redirect_page = FooAuth::get_instance()->options()->get('unauthorized_redirect_page', '');

      if (!empty($redirect_page)) {
        $current_page = $this->get_current_page_url();

        if (!empty($current_page)) {
          return ($current_page === $redirect_page);
        }
      }
      return false;
    }

    private function is_sso_enabled() {
      $do_sso = FooAuth::get_instance()->options()->get('ldap_single_signon', false);
      return ('on' === $do_sso);
    }

    private function is_admin_user($user_id) {
      if (!empty($user_id)) {
        $user = new WP_User($user_id);

        if (!empty($user)) {
          foreach ($user->roles as $user_role) {
            if (strtolower(__('administrator', 'fooauth')) === strtolower($user_role)) {
              return true;
            }
          }
        }
      }
      return false;
    }

    // Get desktop login username and domain
    // =================================================================
    private function get_current_user_info() {
      if (empty($_SERVER['REMOTE_USER'])) return false;

      $current_credentials = explode('\\', $_SERVER['REMOTE_USER']);
      // Server is not escaping slashes
			if(count($current_credentials) === 2) {
				list($ad_domain, $ad_username) = $current_credentials;
			}
			// Server is escaping slashes, this happens on derhrweb01.mgsops.net      
			if(count($current_credentials) === 3) {
				list($ad_domain, ,$ad_username) = $current_credentials;
			}

      return array(
        'domain' => $ad_domain,
        'username' => $ad_username
      );
    }

    private function get_actual_username($remote_user) {
      $username = $remote_user['username'];

      if (is_user_logged_in()) {

        $logged_in_user = wp_get_current_user();

        if ($username !== $logged_in_user->user_login) {
          $username = $logged_in_user->user_login;
        }
      }
      return $username;
    }

    // Update user details in Wordpress
    // =================================================================
    private function update_user_details($username, $user_id) {
      $auto_update_user = FooAuth::get_instance()->options()->get('auto_user_updates', false);

      if ('on' === $auto_update_user) {
        $user = $this->get_details_from_ldap($username);

        $userdata = array(
          'ID' => $user_id,
          'first_name' => $user['name'],
          'last_name' => $user['surname'],
          'display_name' => $user['display_name']
        );

        wp_update_user($userdata);
        update_user_meta($user_id, 'department', $user['department']);
				update_user_meta($user_id, 'location', $user['location']);
				update_user_meta($user_id, 'manager', $user['manager']);
      }
    }
    // register a new user in Wordpress
    // =================================================================
    private function register_new_user($username) {
      $user = $this->get_details_from_ldap($username);

      if (!is_wp_error($user)) {
        $options = FooAuth::get_instance()->options();
        $default_role = $options->get('default_role', 'pending');

        $random_password = wp_generate_password(12, false);

        $userdata = array(
          'first_name' => $user['name'],
          'last_name' => $user['surname'],
          'display_name' => $user['display_name'],
          'role' => $default_role,
          'user_pass' => $random_password,
          'user_login' => $username,
          'user_email' => $user['email']
        );

        $user_id = wp_insert_user($userdata);

        add_user_meta($user_id, 'department', $user['department'], true);
				add_user_meta($user_id, 'location', $user['location'], true);
				add_user_meta($user_id, 'manager', $user['manager'], true);

        return $user_id;
      }
      return $user;
    }



    // Add Auth boxes to the post/page edit screens
    // =================================================================
    function auth_metabox_setup() {
      add_action('add_meta_boxes', array($this, 'add_auth_metaboxes'));
      add_action('save_post', array($this, 'save_post_authorized_groups'), 10, 2);
    }

    function add_auth_metaboxes() {
      add_meta_box('fooauth_authorized_groups', esc_html__('Authorized Groups', 'fooath'), array($this, 'authorized_group_metabox'), 'post', 'side', 'default');
      add_meta_box('fooauth_authorized_groups', esc_html__('Authorized Groups', 'fooath'), array($this, 'authorized_group_metabox'), 'page', 'side', 'default');
    }

    function save_post_authorized_groups($post_id, $post) {
      if (empty($_POST['fooauth_authorized_groups_nonce'])) return false; 

      $foo_auth_nonce = $_POST['fooauth_authorized_groups_nonce'];

      if (!isset($foo_auth_nonce) || !wp_verify_nonce($foo_auth_nonce, basename(__FILE__))) return $post_id;

      $post_type = get_post_type_object($post->post_type);

      if (!current_user_can($post_type->cap->edit_post, $post_id)) return $post_id;

      $meta_key = 'fooauth-authorized-groups';
      if($_POST[$meta_key]) {
        $new_meta_value = implode(',', $_POST[$meta_key] );
        $meta_value = get_post_meta($post_id, $meta_key, true);
      }

      if (!empty($new_meta_value) && empty($meta_value)) {
        add_post_meta($post_id, $meta_key, $new_meta_value, true);
      } else if (!empty($new_meta_value) && $new_meta_value != $meta_value) {
        update_post_meta($post_id, $meta_key, $new_meta_value);
      } else if (empty($new_meta_value) && !empty($meta_value)) {
        delete_post_meta($post_id, $meta_key, $meta_value);
      }
    }

    function authorized_group_metabox($object, $box) {
      // Get all location groups from FooAuth Plugin, trim white space and sort alphabetically
      $authorized_groups = explode(',', FooAuth::get_instance()->options()->get('authorized_groups', '') );
      $authorized_groups = array_map('trim', $authorized_groups);
      sort($authorized_groups);
      
      // Get this content's selected location groups
      $selected_authorized_groups = explode(',', get_post_meta($object->ID, 'fooauth-authorized-groups', true) );
      // Set nonce for the field
      wp_nonce_field(basename(__FILE__), 'fooauth_authorized_groups_nonce');
      ?>
      
      <p class="post-attributes-label-wrapper">
        <label class="post-attributes-label" for="fooauth-authorized-groups"><?php _e('Locations', 'fooauth'); ?></label>
      </p>
      
      <p><?php _e('Choose which location groups can view this content.', 'fooauth'); ?></p>

      <select multiple size="<?php echo count($authorized_groups) + 1; ?>"  class="widefat" name="fooauth-authorized-groups[]" id="fooauth-authorized-groups">
      <?php if($selected_authorized_groups[0] === '') {
        echo '<option value="" selected>All locations</option>';
      } else {
        echo '<option value="">All locations</option>';
      } ?>
      

      <?php foreach($authorized_groups as $value) {
        $selected = '';
        if(in_array($value, $selected_authorized_groups)) {
          $selected = ' selected';
        }
        
        printf(
          '<option value="%s" %s>%s</option>',
          $value,
          $selected,
          $value
        );
      };?>
      </select>      

      <p><?php _e('Hold down CTRL or SHIFT to select multiple locations.', 'fooauth'); ?></p>

    <?php
    }

    // Add new columns to the page listing edit screen, and populate with data
    // =================================================================		
    function add_page_columns( $columns ) {
      $columns['authorised-group'] 	= 'Authorised Group';
      return $columns;
    }

    function add_page_columns_data( $column_name, $post_id) {
      switch( $column_name ) {
          case 'authorised-group':
            echo '<div id="fooauth-authorized-groups-' . $post_id . '">' . get_post_meta( $post_id, 'fooauth-authorized-groups', true ) . '</div>';
          break;
      }
    }

    function add_to_bulk_quick_edit_custom_box( $column_name, $post_type ) {
      switch ( $post_type ) {
          case 'page':

            switch( $column_name ) {
                case 'authorised-group':
                  // Get all location groups from FooAuth Plugin, trim white space and sort alphabetically
                  $authorized_groups = explode(',', FooAuth::get_instance()->options()->get('authorized_groups', '') );
                  $authorized_groups = array_map('trim', $authorized_groups);
                  sort($authorized_groups);  
                  
                  ?><fieldset class="inline-edit-col-left">
                    <style>
                    #wpbody-content .bulk-edit-row-page  .inline-edit-col-right,
                    #wpbody-content .bulk-edit-row-page  .inline-edit-col-left,
                    #wpbody-content .quick-edit-row-page .inline-edit-col-left, 
                    #wpbody-content .quick-edit-row-page .inline-edit-col-right {
                      width: 32%;
                    }
                    </style>
                      <div class="inline-edit-group wp-clearfix">
                        <label class="alignleft">
                            <span class="title">Locations</span>
                            <select multiple size="<?php echo count($authorized_groups) + 1; ?>"  class="widefat" name="fooauth-authorized-groups[]">
                              <option value="">All locations</option>

                            <?php foreach($authorized_groups as $value) {                            
                              printf(
                                '<option value="%s">%s</option>',
                                $value,
                                $value
                              );
                            };?>
                            </select>
                        </label>
                      </div>
                  </fieldset><?php
                  break;
            }
            break;

      }
    }

    function save_post( $post_id, $post ) {
      $meta_key = 'fooauth-authorized-groups';

      // don't save for autosave
      if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE )
          return $post_id;

      // dont save for revisions
      if ( isset( $post->post_type ) && $post->post_type == 'revision' )
          return $post_id;

      switch( $post->post_type ) {   
        case 'page':             
        // Because this action is run in several places, checking for the array key keeps WordPress from editing
        // data that wasn't in the form, i.e. if you had this post meta on your "Quick Edit" but didn't have it
        // on the "Edit Post" screen.       
        if($_POST[$meta_key]) {
          $new_meta_value = implode(',', $_POST[$meta_key] );
          $meta_value = get_post_meta($post_id, $meta_key, true);
        }

        if (!empty($new_meta_value) && empty($meta_value)) {
          add_post_meta($post_id, $meta_key, $new_meta_value, true);
        } else if (!empty($new_meta_value) && $new_meta_value != $meta_value) {
          update_post_meta($post_id, $meta_key, $new_meta_value);
        } else if (empty($new_meta_value) && !empty($meta_value)) {
          delete_post_meta($post_id, $meta_key, $meta_value);
        }

        break;      
      }
    }

    
    function save_bulk_edit() {
      $ajax = 'authorised_groups';
      $meta_key = 'fooauth-authorized-groups';
      
      // get our variables
      $post_ids = ( isset( $_POST[ 'post_ids' ] ) && !empty( $_POST[ 'post_ids' ] ) ) ? $_POST[ 'post_ids' ] : array();
      $authorised_groups = ( isset( $_POST[ $ajax ] ) && !empty( $_POST[ $ajax ] ) ) ? $_POST[ $ajax ] : ' ';
      // if everything is in order
      if ( !empty( $post_ids ) && is_array( $post_ids ) && !empty( $authorised_groups ) ) {
          foreach( $post_ids as $post_id ) {
            update_post_meta( $post_id, $meta_key, $authorised_groups );
          }
      }
    }



    function enqueue_edit_scripts() {   
      wp_enqueue_script( 'rachel-carden-admin-edit', plugin_dir_url( __FILE__ ) .'quick_edit.js', array( 'jquery', 'inline-edit-post' ), '', true );
    }

    // Check user access
    // =================================================================
    public function is_user_authorized($username, $authorized_groups = '') {
      if (empty($authorized_groups)) {
        $authorized_groups = FooAuth::get_instance()->options()->get('authorized_groups', '');
      }

      $user_id = username_exists($username);

      if ($this->is_admin_user($user_id)) {
        return true;
      }

      if (isset($user_id)) {
        $user_location = get_user_meta($user_id, 'location');
      } 

      if (!empty($authorized_groups)) {
        if (!empty($user_location)) {
          $user_group_array = array_map('trim', $user_location);

          $authorized_groups_array = explode(',', $authorized_groups);
          $authorized_groups_array = array_map('trim', $authorized_groups_array);

          foreach ($user_group_array as $user_group) {
            foreach ($authorized_groups_array as $authorized_group) {
              if (strtolower($user_group) === strtolower($authorized_group)) {
                return true;
              }
            }
          }
        }
        return false;
      }
      return true;
    }
    public function user_authorization_check($user_login) {
      //if the user is not on the redirect page, check if they are authorized to login to the site
      if (!$this->is_on_redirect_page() && !$this->is_user_authorized($user_login)) {
        //User is not authorized to login to the site. Redirect to a selected page
        $this->redirect_unauthorized_users();
      }
    }

    public function check_user_authorization() {
      $current_post = get_post();
      $meta_key = 'fooauth-authorized-groups';

      $authorized_groups = get_post_meta($current_post->ID, $meta_key, true);

      if (!empty($authorized_groups)) {
        $user = $this->get_current_user_info();

        if (!$user) return;

        if ('post' === $current_post->post_type && !$this->is_user_authorized($this->get_actual_username($user), $authorized_groups)) {
          $this->redirect_unauthorized_users();
        }
        if ('page' === $current_post->post_type && !$this->is_user_authorized($this->get_actual_username($user), $authorized_groups)) {
          $this->redirect_unauthorized_users();
        }
      }
    }

    public function redirect_unauthorized_users() {
      $redirect_url = FooAuth::get_instance()->options()->get('unauthorized_redirect_page', '');
      wp_redirect($redirect_url);
      exit;
    }



    // Exclude posts from a user based on location
    // =================================================================
    private $excluded_posts = false;
    private $filter_loop = true;

    private function get_excluded_posts() {
      if ($this->excluded_posts === false) {
        $excluded_posts = array();

        $this->filter_loop = false;

        //get all the posts for the site
        $query = new WP_Query(array('post_type' => 'post'));

        $site_posts = $query->get_posts();

        $this->filter_loop = true;

        $user = $this->get_current_user_info();

        foreach ($site_posts as $site_post) {
          $authorized_groups = get_post_meta($site_post->ID, 'fooauth-authorized-groups', true);

          if (!empty($authorized_groups)) {
            if (!$this->is_user_authorized($this->get_actual_username($user), $authorized_groups)) {
              $excluded_posts[] = $site_post->ID;
            }
          }
        }
        $this->excluded_posts = $excluded_posts;
      }
      return $this->excluded_posts;
    }

    public function filter_allowed_posts($query) {

      if ($this->filter_loop === false) return;

      //exclude all posts from the main query that the user is not authorized to view
      $excluded_posts = $this->get_excluded_posts();

      if (!empty($excluded_posts)) {
        $query->set('post__not_in', $excluded_posts);
      }
    }






    // Add new columns to the user's listing admin page, and populate with data from AD
    // =================================================================		
		function add_user_columns($column) {
			$column['location'] 	= 'Location';
			$column['department'] = 'Department';
			$column['manager'] 		= 'Manager';

			return $column;
		}		


		// Add details to the columns
		function add_user_column_data( $val, $column_name, $user_id ) {
			$user = get_userdata($user_id);

			switch ($column_name) {
				case 'manager' :
					return $user->manager;
				break;
				case 'location' :
					return $user->location;
				break;
				case 'department' :
					return $user->department;
				break;
			}
			return;
		}



  }
}